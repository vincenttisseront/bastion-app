"""Nginx auth_request handler for subdomain SSO vhosts.

Enforces AccessGrant (launch+) after session validation so revoking a grant
cuts direct URL access immediately — without waiting for cookie expiry.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from typing import Mapping, Optional

import httpx
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app import re_safe
from app.audit import log_action
from app.auth.auth_request import (
    _get_oauth2_auth,
    get_realm_proxy_url,
    is_rfc1918,
    safe_groups_header,
    safe_header_value,
)
from app.bastion.m2m_policy import app_uri_is_m2m_bypass, m2m_credential_allows
from app.auth.breakglass import (
    COOKIE_NAME,
    process_breakglass_auth_request,
)
from app.database import get_db, release_db_connection
from app.models import App
from app.rbac.effective_access_service import user_can_launch_application
from app.request_client_ip import client_ip_from_request
from app.robotic.app_session_presence import has_app_session_cookie
from app.security.session_binding_service import evaluate_sso_binding
from app.sso_settings import Settings, get_settings
from app.web.user_context import parse_groups_header

logger = logging.getLogger(__name__)

router = APIRouter(tags=["subdomain-auth"])

# CrushFTP bounces invalidated sessions to this URI (302 + cookie wipe).
_CRUSHFTP_LOGIN_URI = "/WebInterface/login.html"
_CRUSHAUTH_RE = re_safe.compile(r"(?:^|;\s*)CrushAuth=([^;]+)")


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


def _allow_identity_headers(
    *,
    app_slug: str,
    auth_source: str,
    keycloak_user_id: str = "",
    email: str = "",
    preferred: str = "",
    groups: list[str] | None = None,
) -> dict[str, str]:
    """Headers returned on auth_request 200 for nginx → upstream SSO apps.

    Bastion gate alone does not create an upstream session. Apps that support
    trusted-header SSO (e.g. Open WebUI ``WEBUI_AUTH_TRUSTED_EMAIL_HEADER``)
    consume the X-Forwarded-* aliases that nginx maps from these values.

    Email is required for most trusted-header apps: prefer the IdP email claim,
    else a preferred username that already looks like an email. Upstreams key
    accounts on this header; that is safe because every account comes from the
    AD through Keycloak, so usernames (UPN) are never user-chosen.

    Every value goes through ``safe_header_value``: one that cannot be emitted
    is omitted instead of failing the whole auth_request with a 500.
    """
    subject = safe_header_value(keycloak_user_id)
    email_l = safe_header_value(email)
    preferred_l = safe_header_value(preferred)
    if not email_l and "@" in preferred_l:
        email_l = preferred_l
    user = subject or preferred_l or email_l
    display = preferred_l or email_l or user
    headers: dict[str, str] = {
        "X-Auth-Source": auth_source,
        "X-Auth-User": user,
        "X-Auth-App": app_slug,
    }
    if email_l:
        # Dual names: nginx maps X-Auth-Email → X-Forwarded-Email / X-Remote-User;
        # some stacks also inspect X-Auth-Request-Email (oauth2-proxy convention).
        headers["X-Auth-Email"] = email_l
        headers["X-Auth-Request-Email"] = email_l
    if preferred_l or email_l:
        headers["X-Auth-Preferred-Username"] = preferred_l or email_l
    if display:
        headers["X-Auth-Display-Name"] = display
    groups_value = safe_groups_header(groups or [])
    if groups_value:
        headers["X-Auth-Groups"] = groups_value
    return headers


def _allow_cache_headers(settings: Settings, uri: str) -> dict[str, str]:
    """Let bastion-nginx reuse this ALLOW for a few seconds (proxy_cache).

    Only for a fully authenticated decision (SSO session + AccessGrant + app
    session cookie). nginx keys the entry on vhost + client IP + exact Cookie
    jar, so only the same session can hit it; nothing is cached without this
    header. The CrushFTP login bounce stays uncached (diagnostic log below).
    """
    ttl = int(getattr(settings, "subdomain_auth_cache_seconds", 0) or 0)
    if ttl <= 0 or (uri or "").startswith(_CRUSHFTP_LOGIN_URI):
        return {}
    return {"X-Accel-Expires": str(ttl)}


def _deny_no_app_session(app: App) -> Response:
    return Response(
        status_code=401,
        headers={
            "X-Auth-Error": "no-app-session",
            "X-Auth-App": app.slug,
        },
    )


def _require_app_session_cookie(app: App | None, cookie_header: str) -> Response | None:
    if app is None:
        return None
    if has_app_session_cookie(app, cookie_header):
        return None
    return _deny_no_app_session(app)


# Denied auth subrequests are not cached by nginx and a single page load fires
# dozens of them: one audit row (INSERT + COMMIT + SIEM forward) per request
# let an anonymous or unauthorized client grow the audit trail without bound.
# Keep one row per (actor, target, reason) per window — the signal survives,
# the flood does not.
_DENY_AUDIT_TTL_SECONDS = 60.0
_DENY_AUDIT_MAX_KEYS = 4096
_deny_audit_seen: dict[tuple[str, str, str], float] = {}
_deny_audit_lock = threading.Lock()


def _should_audit_deny(actor: str, target: str, reason: str) -> bool:
    """True the first time this denial is seen within the window (thread-safe)."""
    now = time.monotonic()
    key = (actor, target, reason)
    with _deny_audit_lock:
        last = _deny_audit_seen.get(key)
        if last is not None and now - last < _DENY_AUDIT_TTL_SECONDS:
            return False
        if len(_deny_audit_seen) >= _DENY_AUDIT_MAX_KEYS:
            cutoff = now - _DENY_AUDIT_TTL_SECONDS
            for stale in [k for k, seen in _deny_audit_seen.items() if seen < cutoff]:
                del _deny_audit_seen[stale]
            if len(_deny_audit_seen) >= _DENY_AUDIT_MAX_KEYS:
                # Still full of live keys: start over rather than grow.
                _deny_audit_seen.clear()
        _deny_audit_seen[key] = now
        return True


def reset_deny_audit_throttle() -> None:
    """Tests: forget which denials were already audited."""
    with _deny_audit_lock:
        _deny_audit_seen.clear()


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
    if _should_audit_deny(actor or "unknown", app.slug, "access_denied_no_grant"):
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
        status_code=401,
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
    host_hint = (host or "").split(":")[0].strip().lower()[:80] or "-"
    if _should_audit_deny("anonymous", host_hint, "no_app_for_host"):
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
    from app.auth.auth_request import _native_oidc_auth_response

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
        realm_slug=_header(native.headers, "X-Auth-Request-Realm") or None,
    )


@dataclass(frozen=True)
class _SubdomainAuthState:
    """What the IdP round-trip and the second DB phase need (no ORM objects)."""

    original_host: str
    original_uri: str
    client_ip: str
    cookie_header: str
    app_id: int
    app_slug: str
    app_realm_slug: str | None
    proxy_url: str


def _subdomain_auth_before_idp(
    request: Request,
    db: Session,
    settings: Settings,
) -> Response | _SubdomainAuthState:
    """Steps 1–3a (bypass, app, M2M, native session) — sync, runs in a worker thread."""
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

    # 1. RFC1918 bypass — gated by RFC1918_BYPASS_ENABLED (default false).
    # F-04 (2026-07-25): subdomain must honour settings flag; default OFF like portal.
    # Portal /internal/oauth2-auth never applies this path.
    # When enabled: skip AccessGrant, but still forward session identity when a
    # bastion_session is present — trusted-header upstreams need X-Auth-Email.
    # Anonymous LAN 200 only if no session.
    if settings.rfc1918_bypass_enabled and is_rfc1918(client_ip, settings.rfc1918_cidrs):
        from app.auth.auth_request import _native_oidc_auth_response

        lan_app = _resolve_app_by_host(db, original_host)
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
            return Response(
                status_code=200,
                headers=_allow_identity_headers(
                    app_slug=lan_app.slug if lan_app is not None else "lan",
                    auth_source="rfc1918-bypass+oidc-native",
                    keycloak_user_id=keycloak_user_id,
                    email=email,
                    preferred=preferred,
                    groups=groups,
                ),
            )
        return Response(
            status_code=200,
            headers={"X-Auth-Source": "rfc1918-bypass"},
        )

    app = _resolve_app_by_host(db, original_host)
    if not app:
        return _deny_no_app(
            db,
            host=original_host,
            uri=original_uri,
            ip_address=client_ip,
        )

    # Declarative M2M: path bypass (defense in depth if auth_request still hits)
    # or Basic/Bearer on the same URL as browser SSO (upstream validates).
    if app_uri_is_m2m_bypass(app, original_uri):
        return Response(
            status_code=200,
            headers={"X-Auth-Source": "m2m-path-bypass"},
        )
    m2m_source = m2m_credential_allows(
        app, request.headers.get("Authorization")
    )
    if m2m_source:
        return Response(
            status_code=200,
            headers={"X-Auth-Source": m2m_source},
        )

    # 3a. Prefer native bastion_session (same cutover as /internal/oauth2-auth),
    # then oauth2-proxy. Native check needs the DB; release only before httpx.
    app_id = app.id
    app_slug = app.slug
    app_realm_slug = app.realm_slug
    proxy_url = get_realm_proxy_url(app.realm_slug, settings, db)

    from app.auth.auth_request import _native_oidc_auth_response

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
            realm_slug=_header(native.headers, "X-Auth-Request-Realm") or None,
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

        missing_app_session = _require_app_session_cookie(app_row, cookie_header)
        if missing_app_session is not None:
            return missing_app_session

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
                **_allow_identity_headers(
                    app_slug=app_slug,
                    auth_source=auth_source,
                    keycloak_user_id=keycloak_user_id,
                    email=email,
                    preferred=preferred,
                    groups=groups,
                ),
                **_allow_cache_headers(settings, original_uri),
            },
        )

    # auth_request is high-concurrency — never hold a pool slot across httpx.
    release_db_connection(db)
    return _SubdomainAuthState(
        original_host=original_host,
        original_uri=original_uri,
        client_ip=client_ip,
        cookie_header=cookie_header,
        app_id=app_id,
        app_slug=app_slug,
        app_realm_slug=app_realm_slug,
        proxy_url=proxy_url,
    )


def _subdomain_auth_after_idp(
    request: Request,
    db: Session,
    settings: Settings,
    state: _SubdomainAuthState,
    *,
    oauth2_ok: bool,
    oauth2_headers: Mapping[str, str],
    oauth2_unreachable: bool,
) -> Response:
    """Steps 3b–5 (grant, presence, break-glass, deny) — sync, worker thread."""
    original_host = state.original_host
    original_uri = state.original_uri
    client_ip = state.client_ip
    cookie_header = state.cookie_header
    app_id = state.app_id
    app_slug = state.app_slug
    app_realm_slug = state.app_realm_slug

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
            realm_slug=app_realm_slug,
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

        missing_app_session = _require_app_session_cookie(app_row, cookie_header)
        if missing_app_session is not None:
            return missing_app_session

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
                **_allow_identity_headers(
                    app_slug=app_slug,
                    auth_source="oidc",
                    keycloak_user_id=keycloak_user_id,
                    email=email,
                    preferred=preferred,
                    groups=groups,
                ),
                **_allow_cache_headers(settings, original_uri),
            },
        )

    # 3b. Break-glass — emergency admin: allow all apps without AccessGrant.
    # LAN recovery when IdP is down; requiring grants would block that path.
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
        bg_user = result.username or "breakglass"
        return Response(
            status_code=200,
            headers=_allow_identity_headers(
                app_slug=app_slug,
                auth_source="breakglass",
                keycloak_user_id="",
                email="",
                preferred=bg_user,
                groups=None,
            ),
        )

    if oauth2_unreachable:
        # Must be 401 (or 403): auth_request treats 5xx as client 500 with
        # upstream=- (wikijs symptom). Redirect to portal login / break-glass.
        return Response(
            status_code=401,
            headers={"X-Auth-Error": "oauth2-unreachable"},
        )
    # Unauthenticated — nginx error_page 401 → @portal_redirect → /auth/login.
    # Distinct from 403 (authenticated, no AccessGrant).
    from app.auth.auth_request import extract_oidc_session_cookie_raw

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


@router.get("/internal/subdomain-auth")
async def subdomain_auth(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    """
    auth_request handler for subdomain SSO vhosts.

    Expected Nginx headers (from subdomain_auth_common.conf.j2):
        X-Original-Host — vhost FQDN (e.g. transfer.example.com)
        X-Original-URI  — requested URI
        X-Real-IP         — client source IP
        Cookie            — client cookies (bastion_session / oauth2-proxy / break-glass)

    Decision flow:
        1. RFC1918 bypass (if RFC1918_BYPASS_ENABLED) -> 200 (LAN, no identity —
           no AccessGrant check). Default OFF; IP via client_ip_from_request
           (trusted proxy only).
        2. App resolution       -> 401 if no app for this Host
        3. Session              -> native bastion_session, then oauth2-proxy, then
           break-glass cookie
        4. Authorization        -> AccessGrant launch+ via get_effective_apps_for_user
           Break-glass: full access to all apps (emergency admin; no grant required)
        5. Deny                 -> 401 access_denied_no_grant (authenticated but not
           authorized). Must stay 401/2xx — nginx auth_request turns any other
           status (including legacy 403) into a client HTTP 500 with upstream=-.
    """
    # A1: every SQL step runs in the threadpool — only the oauth2-proxy call
    # stays on the event loop (single uvicorn worker serves all auth).
    pre = await run_in_threadpool(_subdomain_auth_before_idp, request, db, settings)
    if isinstance(pre, Response):
        return pre

    oauth2_ok = False
    oauth2_headers: Mapping[str, str] = {}
    oauth2_unreachable = False
    try:
        # Lifespan keep-alive client (same as portal /internal/oauth2-auth) —
        # not a fresh TCP connection + client per auth_request.
        resp = await _get_oauth2_auth(
            request, f"{pre.proxy_url}/oauth2/auth", pre.cookie_header
        )
        if resp.status_code in (200, 202):
            oauth2_ok = True
            oauth2_headers = resp.headers
    except httpx.RequestError:
        # Fall through to break-glass; if neither works, return 401 below
        # (never 503 — nginx auth_request maps unexpected codes to client 500).
        oauth2_unreachable = True

    return await run_in_threadpool(
        _subdomain_auth_after_idp,
        request,
        db,
        settings,
        pre,
        oauth2_ok=oauth2_ok,
        oauth2_headers=oauth2_headers,
        oauth2_unreachable=oauth2_unreachable,
    )
