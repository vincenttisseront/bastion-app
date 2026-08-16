"""ActiveSync / Autodiscover auth_request — Basic or SSO, no oauth2 HTML redirect."""

from __future__ import annotations

import base64
import logging
import re
import time
from typing import Mapping

import httpx
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth import get_realm_proxy_url
from app.breakglass import COOKIE_NAME, process_breakglass_auth_request
from app.database import get_db, release_db_connection
from app.models import ActiveSyncDevice, App
from app.rbac.effective_access_service import user_can_launch_application
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings
from app.subdomain import activesync_device_service as device_service
from app.subdomain.eas_device import extract_eas_device, is_autodiscover_uri
from app.subdomain.subdomain_auth import _header, _resolve_app_by_host
from app.web.user_context import parse_groups_header

logger = logging.getLogger(__name__)

router = APIRouter(tags=["activesync-auth"])

# Throttle allow audits (EAS is chatty); always log denials.
_allow_log_ts: dict[tuple[str, str, str, str], float] = {}
_ALLOW_LOG_INTERVAL_SEC = 60.0

_EAS_PATH_RE = re.compile(
    r"(?i)^/(Microsoft-Server-ActiveSync|(AutoDiscover|autodiscover)(/|$))",
)


def classify_mobile_client(user_agent: str) -> str:
    ua = (user_agent or "").lower()
    if "apple-iphone" in ua or "iphone" in ua:
        return "iphone"
    if "apple-ipad" in ua or "ipad" in ua:
        return "ipad"
    if "apple-mail" in ua or ("mac os x" in ua and "mail" in ua):
        return "apple_mail"
    if "outlook" in ua or "microsoft office" in ua:
        return "outlook"
    if "android" in ua or "dalvik" in ua:
        return "android"
    if "activesync" in ua or "eas" in ua:
        return "activesync_generic"
    return "other"


def is_activesync_uri(uri: str) -> bool:
    path = (uri or "/").split("?", 1)[0]
    return bool(_EAS_PATH_RE.match(path))


def _basic_username(authorization: str) -> str | None:
    raw = (authorization or "").strip()
    if not raw.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(raw[6:].strip()).decode("utf-8", errors="replace")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    user, _sep, _pw = decoded.partition(":")
    user = user.strip()
    return user or None


def reset_allow_log_throttle() -> None:
    """Drop the allow-audit throttle state (tests)."""
    _allow_log_ts.clear()


def _should_log_allow(
    app_slug: str, client_ip: str, actor: str, device_id: str | None = None
) -> bool:
    # device_id is part of the key: two phones of the same user behind one NAT
    # would otherwise mask each other and leave the fleet unauditable.
    key = (app_slug, client_ip or "-", actor or "-", device_id or "-")
    now = time.monotonic()
    last = _allow_log_ts.get(key, 0.0)
    if now - last < _ALLOW_LOG_INTERVAL_SEC:
        return False
    _allow_log_ts[key] = now
    # Bound cache size
    if len(_allow_log_ts) > 5000:
        _allow_log_ts.clear()
        _allow_log_ts[key] = now
    return True


def _log_activesync(
    db: Session,
    *,
    action: str,
    app: App | None,
    actor: str,
    client_ip: str | None,
    uri: str,
    host: str,
    user_agent: str,
    auth_source: str | None = None,
    client_kind: str | None = None,
    reason: str | None = None,
    device_id: str | None = None,
    device_type: str | None = None,
    device_status: str | None = None,
) -> None:
    details: dict = {
        "uri": (uri or "/")[:1024],
        "host": (host or "")[:255] or None,
        "user_agent": (user_agent or "")[:512] or None,
        "client_kind": client_kind or classify_mobile_client(user_agent),
        "activesync": True,
    }
    if auth_source:
        details["auth_source"] = auth_source
    if reason:
        details["reason"] = reason
    # Promote the device out of the raw query string: it used to be readable
    # only by hand-parsing ``uri``.
    if device_id:
        details["device_id"] = device_id
        from app.subdomain.eas_device_identity import describe_eas_device

        identity = describe_eas_device(
            device_id=device_id,
            device_type=device_type,
            user_agent=user_agent,
            client_kind=details["client_kind"],
        )
        for key in ("apple_serial", "model_label", "display_name"):
            value = identity.get(key)
            if value:
                details[key] = value
    if device_type:
        details["device_type"] = device_type
    if device_status:
        details["device_status"] = device_status
    if app is not None:
        details["application_id"] = app.id
        details["allow_activesync"] = bool(app.allow_activesync)
        details["activesync_device_control"] = bool(app.activesync_device_control)
    log_action(
        db,
        actor=actor or "anonymous",
        action=action,
        target=(app.slug if app else (host or "")[:255]) or None,
        details=details,
        ip_address=client_ip or None,
    )


def _is_device_exempt(uri: str, method: str) -> bool:
    """Requests that must pass whatever the device inventory says.

    OPTIONS is protocol negotiation and carries no DeviceId — denying it stops
    any client from even connecting. Autodiscover is account setup, and cutting
    it breaks the initial configuration rather than a single device.
    """
    return method.upper() == "OPTIONS" or is_autodiscover_uri(uri)


def _evaluate_device(
    db: Session,
    *,
    app: App,
    actor: str,
    device_id: str | None,
    device_type: str | None,
    exempt: bool,
    uri: str,
    host: str,
    user_agent: str,
    client_kind: str,
    client_ip: str | None,
    enforce: bool = True,
) -> tuple[ActiveSyncDevice | None, Response | None]:
    """Inventory the sighting and decide. Returns ``(device, deny_response)``.

    Best-effort by construction: any inventory failure yields ``(None, None)``,
    i.e. today's behaviour. A refusal may only come from an explicit decision
    stored in the database, never from broken telemetry.
    """
    if exempt or not device_id:
        return None, None

    user_key = device_service.normalize_user_key(actor)
    if not user_key:
        return None, None

    try:
        device = device_service.record_sighting(
            db,
            app=app,
            user_key=user_key,
            device_id=device_id,
            device_type=device_type,
            user_agent=user_agent,
            client_kind=client_kind,
            client_ip=client_ip,
        )
    except Exception:
        logger.exception("activesync inventory failed device_id=%s", device_id)
        return None, None

    if device is None or not device.blocked_by_admin or not enforce:
        return device, None

    if device_service.should_log_denial(app.id, device_id):
        _log_activesync(
            db,
            action="activesync.denied",
            app=app,
            actor=actor,
            client_ip=client_ip,
            uri=uri,
            host=host,
            user_agent=user_agent,
            client_kind=client_kind,
            reason="device_blocked_by_admin",
            device_id=device_id,
            device_type=device_type,
            device_status=device.status,
        )
    # 403, never 401: a 401 makes iOS/Android loop on the password prompt and
    # convinces the user their account is broken.
    return device, Response(
        status_code=403,
        headers={
            "X-Auth-Error": "activesync-device-not-approved",
            "X-Auth-App": app.slug,
        },
    )


@router.get("/internal/activesync-auth")
async def activesync_auth(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    """auth_request for EAS/Autodiscover locations (no oauth2 HTML redirect).

    Allow when:
      - App has allow_activesync and client sent HTTP Basic (upstream validates password), or
      - Valid OIDC / break-glass session with launch grant (same as subdomain auth).
    Deny with 401 + WWW-Authenticate: Basic (nginx named location also adds the header).
    """
    original_host = request.headers.get("X-Original-Host", "") or request.headers.get("Host", "")
    original_uri = request.headers.get("X-Original-URI", "") or request.url.path
    # Absent until nginx is reloaded with the header — treated as "unknown
    # method", which never blocks.
    original_method = request.headers.get("X-Original-Method", "")
    client_ip = client_ip_from_request(request)
    user_agent = request.headers.get("User-Agent", "")
    cookie_header = request.headers.get("Cookie", "")
    authorization = request.headers.get("Authorization", "")
    client_kind = classify_mobile_client(user_agent)
    device_id, device_type = extract_eas_device(original_uri)
    device_exempt = _is_device_exempt(original_uri, original_method)

    app = _resolve_app_by_host(db, original_host)
    if not app:
        _log_activesync(
            db,
            action="activesync.denied",
            app=None,
            actor="anonymous",
            client_ip=client_ip,
            uri=original_uri,
            host=original_host,
            user_agent=user_agent,
            client_kind=client_kind,
            reason="no_app_for_host",
        )
        return Response(
            status_code=401,
            headers={
                "X-Auth-Error": "no-app-for-host",
                "WWW-Authenticate": 'Basic realm="ActiveSync"',
            },
        )

    if not bool(getattr(app, "allow_activesync", False)):
        _log_activesync(
            db,
            action="activesync.denied",
            app=app,
            actor="anonymous",
            client_ip=client_ip,
            uri=original_uri,
            host=original_host,
            user_agent=user_agent,
            client_kind=client_kind,
            reason="activesync_disabled",
        )
        return Response(
            status_code=401,
            headers={
                "X-Auth-Error": "activesync_disabled",
                "X-Auth-App": app.slug,
                "WWW-Authenticate": 'Basic realm="ActiveSync"',
            },
        )

    # Detected ActiveSync path (or Autodiscover) for an opted-in app.
    if not device_id and not device_exempt:
        try:
            device_service.log_unidentified_device(
                db,
                app=app,
                actor=_basic_username(authorization) or "anonymous",
                uri=original_uri,
                user_agent=user_agent,
                client_kind=client_kind,
                client_ip=client_ip,
            )
        except Exception:
            logger.exception("activesync unidentified log failed host=%s", original_host)

    basic_user = _basic_username(authorization)
    if basic_user:
        actor = basic_user
        device, denied = _evaluate_device(
            db,
            app=app,
            actor=actor,
            device_id=device_id,
            device_type=device_type,
            exempt=device_exempt,
            uri=original_uri,
            host=original_host,
            user_agent=user_agent,
            client_kind=client_kind,
            client_ip=client_ip,
        )
        if denied is not None:
            return denied
        if _should_log_allow(app.slug, client_ip or "", actor, device_id):
            _log_activesync(
                db,
                action="activesync.allowed",
                app=app,
                actor=actor,
                client_ip=client_ip,
                uri=original_uri,
                host=original_host,
                user_agent=user_agent,
                auth_source="basic",
                client_kind=client_kind,
                device_id=device_id,
                device_type=device_type,
                device_status=device.status if device is not None else None,
            )
        return Response(
            status_code=200,
            headers={
                "X-Auth-Source": "basic",
                "X-Auth-User": basic_user,
                "X-Auth-App": app.slug,
            },
        )

    # SSO cookie path (rare for native mail, but useful for some clients)
    app_id = app.id
    app_slug = app.slug
    proxy_url = get_realm_proxy_url(app.realm_slug, settings, db)
    release_db_connection(db)
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{proxy_url}/oauth2/auth",
                headers={"Cookie": cookie_header},
            )
        if resp.status_code in (200, 202):
            oauth2_headers: Mapping[str, str] = resp.headers
            keycloak_user_id = _header(
                oauth2_headers, "X-Auth-Request-User", "X-Auth-User"
            )
            groups = parse_groups_header(
                _header(oauth2_headers, "X-Auth-Request-Groups", "X-Auth-Groups")
            )
            email = _header(oauth2_headers, "X-Auth-Request-Email", "X-Auth-Email")
            preferred = _header(
                oauth2_headers,
                "X-Auth-Request-Preferred-Username",
                "X-Auth-Preferred-Username",
            )
            actor = email or preferred or keycloak_user_id or "unknown"
            app = db.get(App, app_id)
            if app is None:
                return Response(
                    status_code=401,
                    headers={
                        "X-Auth-Error": "no_app_for_host",
                        "WWW-Authenticate": 'Basic realm="ActiveSync"',
                    },
                )
            if not user_can_launch_application(
                db,
                application_id=app_id,
                keycloak_user_id=keycloak_user_id or None,
                group_names=groups,
            ):
                _log_activesync(
                    db,
                    action="activesync.denied",
                    app=app,
                    actor=actor,
                    client_ip=client_ip,
                    uri=original_uri,
                    host=original_host,
                    user_agent=user_agent,
                    auth_source="oidc",
                    client_kind=client_kind,
                    reason="access_denied_no_grant",
                )
                return Response(
                    status_code=403,
                    headers={
                        "X-Auth-Error": "access_denied_no_grant",
                        "X-Auth-App": app_slug,
                    },
                )
            device, denied = _evaluate_device(
                db,
                # Never the Keycloak UUID: the inventory is keyed on the same
                # identity Basic Auth sends, or the two never join.
                actor=email or preferred or "",
                app=app,
                device_id=device_id,
                device_type=device_type,
                exempt=device_exempt,
                uri=original_uri,
                host=original_host,
                user_agent=user_agent,
                client_kind=client_kind,
                client_ip=client_ip,
            )
            if denied is not None:
                return denied
            if _should_log_allow(app_slug, client_ip or "", actor, device_id):
                _log_activesync(
                    db,
                    action="activesync.allowed",
                    app=app,
                    actor=actor,
                    client_ip=client_ip,
                    uri=original_uri,
                    host=original_host,
                    user_agent=user_agent,
                    auth_source="oidc",
                    client_kind=client_kind,
                    device_id=device_id,
                    device_type=device_type,
                    device_status=device.status if device is not None else None,
                )
            return Response(
                status_code=200,
                headers={
                    "X-Auth-Source": "oidc",
                    "X-Auth-User": keycloak_user_id or preferred or email or "",
                    "X-Auth-App": app_slug,
                },
            )
    except httpx.RequestError:
        pass

    bg_cookie = request.cookies.get(COOKIE_NAME)
    if bg_cookie:
        result = process_breakglass_auth_request(
            db, request, bg_cookie, settings, rotate=False
        )
        try:
            db.commit()
        except Exception:
            db.rollback()
        if result.ok:
            actor = result.username or "breakglass"
            app = db.get(App, app_id)
            if app is None:
                return Response(
                    status_code=401,
                    headers={
                        "X-Auth-Error": "no_app_for_host",
                        "WWW-Authenticate": 'Basic realm="ActiveSync"',
                    },
                )
            # Break-glass is inventoried but never gated: this is the admin
            # escape hatch and must stay usable to unblock a device.
            device, _denied = _evaluate_device(
                db,
                app=app,
                actor=actor,
                device_id=device_id,
                device_type=device_type,
                exempt=device_exempt,
                uri=original_uri,
                host=original_host,
                user_agent=user_agent,
                client_kind=client_kind,
                client_ip=client_ip,
                enforce=False,
            )
            if _should_log_allow(app_slug, client_ip or "", actor, device_id):
                _log_activesync(
                    db,
                    action="activesync.allowed",
                    app=app,
                    actor=actor,
                    client_ip=client_ip,
                    uri=original_uri,
                    host=original_host,
                    user_agent=user_agent,
                    auth_source="breakglass",
                    client_kind=client_kind,
                    device_id=device_id,
                    device_type=device_type,
                    device_status=device.status if device is not None else None,
                )
            return Response(
                status_code=200,
                headers={
                    "X-Auth-Source": "breakglass",
                    "X-Auth-User": actor,
                    "X-Auth-App": app_slug,
                },
            )

    app = db.get(App, app_id) or app
    _log_activesync(
        db,
        action="activesync.denied",
        app=app,
        actor="anonymous",
        client_ip=client_ip,
        uri=original_uri,
        host=original_host,
        user_agent=user_agent,
        client_kind=client_kind,
        reason="not_authenticated",
        device_id=device_id,
        device_type=device_type,
    )
    return Response(
        status_code=401,
        headers={
            "X-Auth-Error": "not_authenticated",
            "X-Auth-App": app_slug,
            "WWW-Authenticate": 'Basic realm="ActiveSync"',
        },
    )
