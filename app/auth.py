"""Nginx auth_request handler — RFC1918 bypass, break-glass, OIDC proxy."""

import ipaddress
from typing import Mapping, Optional

import httpx
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.admin.export import realm_oauth2_proxy_url
from app.auth_flow import get_default_idp_realm
from app.breakglass import (
    COOKIE_NAME,
    maybe_refresh_breakglass_cookie,
    set_breakglass_cookie,
    validate_breakglass_cookie,
)
from app.database import get_db
from app.models import RealmConfig
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings

router = APIRouter()

# Nginx auth_request_set (vhost_sso_portal.conf.j2) reads only these upstream headers:
#   $upstream_http_x_auth_request_user
#   $upstream_http_x_auth_request_email
#   $upstream_http_x_auth_request_groups
#   $upstream_http_x_auth_request_preferred_username
# Whitelist by prefix — never relay Set-Cookie or other oauth2-proxy headers.
_AUTH_REQUEST_HEADER_PREFIX = "x-auth-request-"


def _forward_auth_request_headers(upstream_headers: Mapping[str, str]) -> dict[str, str]:
    """Copy X-Auth-Request-* headers for Nginx auth_request_set variables."""
    forwarded: dict[str, str] = {}
    for name, value in upstream_headers.items():
        if name.lower().startswith(_AUTH_REQUEST_HEADER_PREFIX) and value:
            # Canonical casing expected by ops docs / oauth2-proxy set_xauthrequest.
            forwarded[
                "-".join(part.capitalize() for part in name.split("-"))
            ] = value
    return forwarded


def is_rfc1918(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(cidr) for cidr in cidrs)
    except ValueError:
        return False


def get_realm_proxy_url(realm_slug: Optional[str], settings: Settings, db: Session) -> str:
    """Resolve oauth2-proxy URL for this realm (DB lookup, fallback to default)."""
    if realm_slug:
        realm = (
            db.query(RealmConfig)
            .filter_by(slug=realm_slug, enabled=True)
            .first()
        )
        if realm:
            return realm_oauth2_proxy_url(realm, settings)
    default_realm = db.query(RealmConfig).filter_by(is_default=True, enabled=True).first()
    if default_realm:
        return realm_oauth2_proxy_url(default_realm, settings)
    return settings.oauth2_proxy_default_url


def _client_ip(request: Request) -> str:
    return client_ip_from_request(request)


def _rfc1918_response(request: Request, settings: Settings) -> Response | None:
    client_ip = _client_ip(request)
    if settings.rfc1918_bypass_enabled and is_rfc1918(client_ip, settings.rfc1918_cidrs):
        return Response(status_code=200, headers={"X-Auth-Source": "rfc1918-bypass"})
    return None


async def _oauth2_proxy_auth_response(
    request: Request,
    settings: Settings,
    db: Session,
) -> Response | None:
    """Call oauth2-proxy /oauth2/auth. None if no IdP; else proxy status (202/401/503)."""
    default_realm = get_default_idp_realm(db)
    if not default_realm:
        return None

    realm_slug = request.headers.get("X-Realm-Slug", default_realm.slug)
    proxy_url = get_realm_proxy_url(realm_slug, settings, db)
    cookie_header = request.headers.get("Cookie", "")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{proxy_url}/oauth2/auth",
                headers={"Cookie": cookie_header},
            )
        # Preserve oauth2-proxy status (often 202 Accepted on success with set_xauthrequest).
        # Forward identity headers so Nginx auth_request_set can inject X-User / X-Email / …
        return Response(
            status_code=resp.status_code,
            headers=_forward_auth_request_headers(resp.headers),
        )
    except httpx.RequestError:
        return Response(status_code=503)


@router.get("/internal/oauth2-auth")
async def oauth2_auth(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    """Portal-only auth_request (`/portal_auth_check`).

    Intentionally does **not** enforce per-app AccessGrant: the catalogue
    (`/apps`, `/dashboard`) must stay reachable for any authenticated user.
    Application URL enforcement lives in ``/internal/subdomain-auth``.
    """
    # Do NOT apply RFC1918 bypass here. Behind Traefik/vpcbr, X-Real-IP is often
    # 10.5.0.0/16 — a bypass would return 200 with no identity and break SSO
    # (auth OK → /dashboard 401 → /auth/login loop). LAN recovery = break-glass.

    # Prefer SSO session over break-glass when both cookies are present.
    # Otherwise a leftover bg_session sends /apps → 302 /dashboard and never hits oauth2.
    oauth2_resp = await _oauth2_proxy_auth_response(request, settings, db)
    if oauth2_resp is not None and oauth2_resp.status_code in (200, 202):
        return oauth2_resp

    bg_cookie = request.cookies.get(COOKIE_NAME)
    secret = settings.vault_portal_internal_token
    if bg_cookie and validate_breakglass_cookie(bg_cookie, secret):
        response = Response(status_code=200, headers={"X-Auth-Source": "breakglass"})
        refreshed = maybe_refresh_breakglass_cookie(bg_cookie, secret)
        if refreshed:
            # Remaining TTL until absolute exp (browser Max-Age hint only; JWT exp is authoritative).
            set_breakglass_cookie(response, refreshed, settings)
        return response

    if oauth2_resp is not None:
        return oauth2_resp

    return Response(
        status_code=401,
        headers={"X-Auth-Error": "no-idp-configured"},
    )


@router.get("/internal/portal-rfc1918-bypass-auth")
async def portal_rfc1918_bypass_auth(
    request: Request,
    settings: Settings = Depends(get_settings),
):
    bypass = _rfc1918_response(request, settings)
    if bypass:
        return bypass
    return Response(status_code=401)
