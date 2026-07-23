"""Nginx auth_request handler for subdomain SSO vhosts.

Enforces AccessGrant (launch+) after session validation so revoking a grant
cuts direct URL access immediately — without waiting for cookie expiry.
"""

from __future__ import annotations

import ipaddress
from typing import Mapping, Optional

import httpx
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth import get_realm_proxy_url
from app.breakglass import (
    COOKIE_NAME,
    decode_breakglass_token,
    maybe_refresh_breakglass_cookie,
    set_breakglass_cookie,
    validate_breakglass_cookie,
)
from app.database import get_db
from app.models import App
from app.rbac.effective_access_service import user_can_launch_application
from app.sso_settings import Settings, get_settings
from app.web.user_context import parse_groups_header

router = APIRouter(tags=["subdomain-auth"])


def _is_rfc1918(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(cidr) for cidr in cidrs)
    except ValueError:
        return False


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
        Cookie            — client cookies (oauth2-proxy / break-glass session)

    Decision flow:
        1. RFC1918 bypass       -> 200 (LAN, no identity — no AccessGrant check)
        2. App resolution       -> 401 if no app for this Host
        3. Session              -> OIDC (oauth2-proxy) or break-glass cookie
        4. Authorization        -> AccessGrant launch+ via get_effective_apps_for_user
           Break-glass: full access to all apps (emergency admin; no grant required)
        5. Deny                 -> 403 (authenticated but not authorized)
    """
    original_host = request.headers.get("X-Original-Host", "")
    client_ip = request.headers.get("X-Real-IP", "")
    cookie_header = request.headers.get("Cookie", "")

    # 1. RFC1918 bypass — no identity available; grant check not applicable.
    if settings.rfc1918_bypass_enabled and _is_rfc1918(client_ip, settings.rfc1918_cidrs):
        return Response(
            status_code=200,
            headers={"X-Auth-Source": "rfc1918-bypass"},
        )

    # 2. App resolution by Host
    app = _resolve_app_by_host(db, original_host)
    if not app:
        return Response(
            status_code=401,
            headers={"X-Auth-Error": "no-app-for-host"},
        )

    # 3a. Prefer OIDC session (same preference as /internal/oauth2-auth).
    proxy_url = get_realm_proxy_url(app.realm_slug, settings, db)
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
            application_id=app.id,
            keycloak_user_id=keycloak_user_id or None,
            group_names=groups,
        ):
            return _deny_no_grant(
                db,
                actor=actor,
                app=app,
                ip_address=client_ip,
                auth_source="oidc",
            )

        return Response(
            status_code=200,
            headers={
                "X-Auth-Source": "oidc",
                "X-Auth-User": keycloak_user_id or preferred or email,
                "X-Auth-App": app.slug,
            },
        )

    # 3b. Break-glass — emergency admin: allow all apps without AccessGrant.
    # Rationale (2026-07-23): break-glass is the LAN recovery path when IdP is down;
    # requiring grants would block the only remaining admin access to subdomain apps.
    bg_cookie = request.cookies.get(COOKIE_NAME)
    secret = settings.vault_portal_internal_token
    if bg_cookie and validate_breakglass_cookie(bg_cookie, secret):
        payload = decode_breakglass_token(bg_cookie, secret) or {}
        username = str(payload.get("sub") or "breakglass")
        response = Response(
            status_code=200,
            headers={
                "X-Auth-Source": "breakglass",
                "X-Auth-User": username,
                "X-Auth-App": app.slug,
            },
        )
        refreshed = maybe_refresh_breakglass_cookie(bg_cookie, secret)
        if refreshed:
            set_breakglass_cookie(response, refreshed, settings)
        return response

    if oauth2_unreachable:
        return Response(status_code=503)
    return Response(status_code=401)
