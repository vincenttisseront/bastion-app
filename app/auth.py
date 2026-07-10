"""Nginx auth_request handler — RFC1918 bypass, break-glass, OIDC proxy."""

import ipaddress
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.breakglass import COOKIE_NAME, validate_breakglass_cookie
from app.database import get_db
from app.models import RealmConfig
from app.sso_settings import Settings, get_settings

router = APIRouter()


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
            return realm.oauth2_proxy_url
    default_realm = db.query(RealmConfig).filter_by(is_default=True, enabled=True).first()
    if default_realm:
        return default_realm.oauth2_proxy_url
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

    realm_slug = request.headers.get("X-Realm-Slug", settings.sso_portal_default_realm_slug)
    proxy_url = get_realm_proxy_url(realm_slug, settings, db)

    cookie_header = request.headers.get("Cookie", "")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{proxy_url}/oauth2/auth",
                headers={"Cookie": cookie_header},
            )
        return Response(status_code=resp.status_code)
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
