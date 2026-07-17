"""Nginx auth_request handler — RFC1918 bypass, break-glass, OIDC proxy."""

import ipaddress
from typing import Mapping, Optional

import httpx
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.admin.export import realm_oauth2_proxy_url
from app.auth_flow import get_default_idp_realm
from app.breakglass import COOKIE_NAME, validate_breakglass_cookie
from app.database import get_db
from app.models import RealmConfig
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
    return request.headers.get("X-Real-IP", request.client.host if request.client else "")


def _rfc1918_response(request: Request, settings: Settings) -> Response | None:
    client_ip = _client_ip(request)
    if settings.rfc1918_bypass_enabled and is_rfc1918(client_ip, settings.rfc1918_cidrs):
        return Response(status_code=200, headers={"X-Auth-Source": "rfc1918-bypass"})
    return None


@router.get("/internal/oauth2-auth")
async def oauth2_auth(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    bypass = _rfc1918_response(request, settings)
    if bypass:
        return bypass

    bg_cookie = request.cookies.get(COOKIE_NAME)
    if bg_cookie:
        if validate_breakglass_cookie(bg_cookie, settings.vault_portal_internal_token):
            return Response(status_code=200, headers={"X-Auth-Source": "breakglass"})
        return Response(status_code=401)

    default_realm = get_default_idp_realm(db)
    if not default_realm:
        return Response(
            status_code=401,
            headers={"X-Auth-Error": "no-idp-configured"},
        )

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


@router.get("/internal/portal-rfc1918-bypass-auth")
async def portal_rfc1918_bypass_auth(
    request: Request,
    settings: Settings = Depends(get_settings),
):
    bypass = _rfc1918_response(request, settings)
    if bypass:
        return bypass
    return Response(status_code=401)
