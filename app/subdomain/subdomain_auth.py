"""Nginx auth_request handler for subdomain SSO vhosts.

Enforces AccessGrant (launch+) after session validation so revoking a grant
cuts direct URL access immediately — without waiting for cookie expiry.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Mapping, Optional

import httpx
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth import get_realm_proxy_url, is_rfc1918
from app.breakglass import (
    COOKIE_NAME,
    process_breakglass_auth_request,
)
from app.database import get_db, release_db_connection
from app.models import App
from app.rbac.effective_access_service import user_can_launch_application
from app.request_client_ip import client_ip_from_request
from app.security.session_binding_service import evaluate_sso_binding
from app.sso_settings import Settings, get_settings
from app.web.user_context import parse_groups_header

logger = logging.getLogger(__name__)

router = APIRouter(tags=["subdomain-auth"])

# CrushFTP bounces invalidated sessions to this URI (302 + cookie wipe).
_CRUSHFTP_LOGIN_URI = "/WebInterface/login.html"
_CRUSHAUTH_RE = re.compile(r"(?:^|;\s*)CrushAuth=([^;]+)")


def _warn_crushftp_login_bounce(
    app: App | None,
    *,
    uri: str,
    cookie_header: str,
    actor: str,
    client_ip: str | None,
) -> None:
    """
    Bastion-side mirror of CrushFTP's
    ``WARNING! User session invalidated due to IP change`` trace.

    An *authenticated* portal user requesting ``/WebInterface/login.html`` on a
    CrushFTP app while still presenting a non-empty ``CrushAuth`` cookie means
    CrushFTP just 302-bounced them: it invalidated the robotic session upstream
    (IP-lock mismatch, expiry, or per-account session limit). The 302 loop is
    otherwise only visible in CrushFTP.log — log it here too so the diagnosis
    shows up in ``docker logs bastion-app``.
    """
    if app is None:
        return
    if (getattr(app, "robotic_driver", None) or "").strip().lower() != "crushftp":
        return
    if not (uri or "").startswith(_CRUSHFTP_LOGIN_URI):
        return
    match = _CRUSHAUTH_RE.search(cookie_header or "")
    if not match:
        return
    value = match.group(1).strip()
    if not value:
        return
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    logger.warning(
        "CrushFTP login bounce: authenticated user hit %s with a live CrushAuth "
        "cookie — CrushFTP invalidated the robotic session upstream (check "
        "CrushFTP.log for 'session invalidated due to IP change' / session "
        "limit). app=%s user=%s client_ip=%s crushauth=%s…#%s",
        _CRUSHFTP_LOGIN_URI,
        app.slug,
        actor,
        client_ip or "-",
        value[:2],
        digest,
    )


def _resolve_app_by_host(db: Session, host: str) -> Optional[App]:
    """Resolve App for this Host header (public_fqdn exact, else first DNS label = slug)."""
    host_clean = (host or "").split(":")[0].strip().lower()
    if not host_clean:
        return None
    by_fqdn = (
        db.query(App)
        .filter(
            App.enabled == True,  # noqa: E712
            App.public_fqdn.isnot(None),
            func.lower(App.public_fqdn) == host_clean,
        )
        .first()
    )
    if by_fqdn:
        return by_fqdn
    slug = host_clean.split(".")[0]
    return (
        db.query(App)
        .filter(App.slug == slug, App.enabled == True)  # noqa: E712
        .first()
    )


def _header(headers: Mapping[str, str], *names: str) -> str:
    lower = {k.lower(): v for k, v in headers.items()}
    for name in names:
        value = lower.get(name.lower())
        if value:
            return value.strip()
    return ""


def _deny_no_grant(
    db: Session,
    *,
    actor: str,
    app: App,
    ip_address: str | None,
    auth_source: str,
    uri: str | None = None,
    host: str | None = None,
) -> Response:
    log_action(
        db,
        actor=actor or "unknown",
        action="access_denied_no_grant",
        target=app.slug,
        details={
            "reason": "access_denied_no_grant",
            "application_id": app.id,
            "auth_source": auth_source,
            "uri": (uri or "/")[:1024],
            "host": (host or "")[:255] or None,
        },
        ip_address=ip_address or None,
    )
    return Response(
        status_code=403,
        headers={
            "X-Auth-Error": "access_denied_no_grant",
            "X-Auth-App": app.slug,
        },
    )


def _deny_no_app(
    db: Session,
    *,
    host: str,
    uri: str | None,
    ip_address: str | None,
) -> Response:
    log_action(
        db,
        actor="anonymous",
        action="access_denied_no_app",
        target=(host or "")[:255] or None,
        details={
            "reason": "no_app_for_host",
            "uri": (uri or "/")[:1024],
            "host": (host or "")[:255] or None,
        },
        ip_address=ip_address or None,
    )
    host_hint = (host or "").split(":")[0].strip().lower()[:80] or "-"
    return Response(
        status_code=401,
        headers={"X-Auth-Error": f"no-app-for-host:{host_hint}"},
    )


def native_subdomain_auth_would_allow(
    db: Session,
    request: Request,
    settings: Settings,
    *,
    host: str,
) -> bool:
    """
    True when ``/internal/subdomain-auth`` would return 200 for this Host
    using only a native ``bastion_session`` (same validation + AccessGrant).

    Used by ``/auth/login`` before bouncing absolute ``rd=`` back to a
    subdomain — mirrors the break-glass login harden (stale cookie must not
    redirect-loop).
    """
    from app.auth import _native_oidc_auth_response

    app = _resolve_app_by_host(db, host)
    if not app:
        return False

    native = _native_oidc_auth_response(request, settings, db)
    if native is None:
        return False

    keycloak_user_id = _header(
        native.headers,
        "X-Auth-Request-User",
        "X-Auth-User",
    )
    groups = parse_groups_header(
        _header(native.headers, "X-Auth-Request-Groups", "X-Auth-Groups")
    )
    return user_can_launch_application(
        db,
        application_id=app.id,
        keycloak_user_id=keycloak_user_id or None,
        group_names=groups,
    )


@router.get("/internal/subdomain-auth")
async def subdomain_auth(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    """
    auth_request handler for subdomain SSO vhosts.

    Expected Nginx headers (from subdomain_auth_common.conf.j2):
        X-Original-Host — vhost FQDN (e.g. transfer.ar-systems.fr)
        X-Original-URI  — requested URI
        X-Real-IP         — client source IP
        Cookie            — client cookies (bastion_session / oauth2-proxy / break-glass)

    Decision flow:
        1. RFC1918 bypass (if RFC1918_BYPASS_ENABLED) -> 200 (LAN, no identity —
           no AccessGrant check). Default OFF (F-04 2026-07-25): align with portal
           until the client-IP chain is proven; re-enable only for confirmed LAN
           need. IP via client_ip_from_request (trusted proxy only).
        2. App resolution       -> 401 if no app for this Host
        3. Session              -> native bastion_session, then oauth2-proxy, then
           break-glass cookie
        4. Authorization        -> AccessGrant launch+ via get_effective_apps_for_user
           Break-glass: full access to all apps (emergency admin; no grant required)
        5. Deny                 -> 403 (authenticated but not authorized)
    """
    # Prefer X-Original-Host (auth_request snippet). Fall back like activesync-auth
    # when a misconfigured edge omits it — Host alone is the vhost FQDN on
    # bastion-nginx subdomain server blocks.
    original_host = (
        request.headers.get("X-Original-Host")
        or request.headers.get("X-Forwarded-Host")
        or request.headers.get("Host")
        or ""
    )
    original_uri = request.headers.get("X-Original-URI", "") or request.url.path
    client_ip = client_ip_from_request(request)
    cookie_header = request.headers.get("Cookie", "")

    # 1. RFC1918 bypass — gated by RFC1918_BYPASS_ENABLED (default false, F-04).
    # Portal /internal/oauth2-auth never applies this path. Subdomain kept the
    # same flag; disabled until reverse01 → nginx-bastion → app IP resolution is
    # validated end-to-end. client_ip_from_request ignores spoofed headers unless
    # the TCP peer is in TRUSTED_PROXY_CIDRS.
    if settings.rfc1918_bypass_enabled and is_rfc1918(client_ip, settings.rfc1918_cidrs):
        return Response(
            status_code=200,
            headers={"X-Auth-Source": "rfc1918-bypass"},
        )

    # 2. App resolution by Host
    app = _resolve_app_by_host(db, original_host)
    if not app:
        return _deny_no_app(
            db,
            host=original_host,
            uri=original_uri,
            ip_address=client_ip,
        )

    # 3a. Prefer native bastion_session (same cutover as /internal/oauth2-auth),
    # then oauth2-proxy. Native check needs the DB; release only before httpx.
    app_id = app.id
    app_slug = app.slug
    proxy_url = get_realm_proxy_url(app.realm_slug, settings, db)

    from app.auth import _native_oidc_auth_response

    native = _native_oidc_auth_response(request, settings, db)
    if native is not None:
        keycloak_user_id = _header(
            native.headers,
            "X-Auth-Request-User",
            "X-Auth-User",
        )
        groups = parse_groups_header(
            _header(native.headers, "X-Auth-Request-Groups", "X-Auth-Groups")
        )
        email = _header(native.headers, "X-Auth-Request-Email", "X-Auth-Email")
        preferred = _header(
            native.headers,
            "X-Auth-Request-Preferred-Username",
            "X-Auth-Preferred-Username",
        )
        actor = email or preferred or keycloak_user_id or "unknown"
        auth_source = "oidc-native"

        if not user_can_launch_application(
            db,
            application_id=app_id,
            keycloak_user_id=keycloak_user_id or None,
            group_names=groups,
        ):
            app = db.get(App, app_id)
            if app is None:
                return Response(
                    status_code=401, headers={"X-Auth-Error": "no-app-for-host"}
                )
            return _deny_no_grant(
                db,
                actor=actor,
                app=app,
                ip_address=client_ip,
                auth_source=auth_source,
                uri=original_uri,
                host=original_host,
            )

        try:
            evaluate_sso_binding(
                db,
                request,
                username=email or preferred or None,
                keycloak_user_id=keycloak_user_id or None,
            )
            db.commit()
        except Exception:
            db.rollback()

        app_row = db.get(App, app_id)
        if app_row is not None:
            from app.web.sessions_service import touch_app_presence

            touch_app_presence(
                db,
                email=email or preferred or keycloak_user_id or "",
                username=preferred or email or None,
                realm=app_row.realm_slug,
                app=app_row,
                source_ip=client_ip,
                auth_source=auth_source,
            )

        _warn_crushftp_login_bounce(
            app_row,
            uri=original_uri,
            cookie_header=cookie_header,
            actor=actor,
            client_ip=client_ip,
        )
        return Response(
            status_code=200,
            headers={
                "X-Auth-Source": auth_source,
                "X-Auth-User": keycloak_user_id or preferred or email,
                "X-Auth-App": app_slug,
            },
        )

    # auth_request is high-concurrency — never hold a pool slot across httpx.
    release_db_connection(db)

    oauth2_ok = False
    oauth2_headers: Mapping[str, str] = {}
    oauth2_unreachable = False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{proxy_url}/oauth2/auth",
                headers={"Cookie": cookie_header},
            )
        if resp.status_code in (200, 202):
            oauth2_ok = True
            oauth2_headers = resp.headers
    except httpx.RequestError:
        # Fall through to break-glass; if neither works, return 503 below.
        oauth2_unreachable = True

    if oauth2_ok:
        # user_id_claim=sub → X-Auth-Request-User is the Keycloak subject UUID.
        keycloak_user_id = _header(
            oauth2_headers,
            "X-Auth-Request-User",
            "X-Auth-User",
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

        if not user_can_launch_application(
            db,
            application_id=app_id,
            keycloak_user_id=keycloak_user_id or None,
            group_names=groups,
        ):
            app = db.get(App, app_id)
            if app is None:
                return Response(
                    status_code=401, headers={"X-Auth-Error": "no-app-for-host"}
                )
            return _deny_no_grant(
                db,
                actor=actor,
                app=app,
                ip_address=client_ip,
                auth_source="oidc",
                uri=original_uri,
                host=original_host,
            )

        try:
            evaluate_sso_binding(
                db,
                request,
                username=email or preferred or None,
                keycloak_user_id=keycloak_user_id or None,
            )
            db.commit()
        except Exception:
            db.rollback()

        app_row = db.get(App, app_id)
        if app_row is not None:
            from app.web.sessions_service import touch_app_presence

            touch_app_presence(
                db,
                email=email or preferred or keycloak_user_id or "",
                username=preferred or email or None,
                realm=app_row.realm_slug,
                app=app_row,
                source_ip=client_ip,
                auth_source="oidc",
            )

        _warn_crushftp_login_bounce(
            app_row,
            uri=original_uri,
            cookie_header=cookie_header,
            actor=actor,
            client_ip=client_ip,
        )
        return Response(
            status_code=200,
            headers={
                "X-Auth-Source": "oidc",
                "X-Auth-User": keycloak_user_id or preferred or email,
                "X-Auth-App": app_slug,
            },
        )

    # 3b. Break-glass — emergency admin: allow all apps without AccessGrant.
    # Rationale (2026-07-23): break-glass is the LAN recovery path when IdP is down;
    # requiring grants would block the only remaining admin access to subdomain apps.
    bg_cookie = request.cookies.get(COOKIE_NAME)
    if bg_cookie:
        # rotate=False: nginx auth_request does not forward Set-Cookie.
        result = process_breakglass_auth_request(
            db, request, bg_cookie, settings, rotate=False
        )
        try:
            db.commit()
        except Exception:
            db.rollback()
        if not result.ok:
            return Response(status_code=401)
        app_row = db.get(App, app_id)
        if app_row is not None:
            from app.web.sessions_service import touch_app_presence

            touch_app_presence(
                db,
                email=result.username or "breakglass",
                username=result.username or "breakglass",
                realm=app_row.realm_slug,
                app=app_row,
                source_ip=client_ip,
                auth_source="breakglass",
            )
        return Response(
            status_code=200,
            headers={
                "X-Auth-Source": "breakglass",
                "X-Auth-User": result.username or "breakglass",
                "X-Auth-App": app_slug,
            },
        )

    if oauth2_unreachable:
        return Response(status_code=503)
    # Unauthenticated — nginx error_page 401 → @portal_redirect → /auth/login.
    # Distinct from 403 (authenticated, no AccessGrant).
    from app.auth import extract_oidc_session_cookie_raw

    had_native = bool(extract_oidc_session_cookie_raw(request, settings))
    cookie_len = len(request.headers.get("Cookie") or "")
    had_x = bool(
        (request.headers.get("X-Bastion-Session-Cookie") or "").strip()
        or (request.headers.get("x-bastion-session-cookie") or "").strip()
        or (request.headers.get("X-Bastion-Session-From-Jar") or "").strip()
        or (request.headers.get("x-bastion-session-from-jar") or "").strip()
    )
    return Response(
        status_code=401,
        headers={
            "X-Auth-Error": (
                "native-session-rejected"
                if had_native
                else f"no-session:ck={cookie_len}:x={int(had_x)}"
            ),
            "X-Auth-App": app_slug,
        },
    )
