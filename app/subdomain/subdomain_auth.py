"""Nginx auth_request handler for subdomain SSO vhosts."""

import ipaddress
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import App
from app.sso_settings import Settings, get_settings

router = APIRouter(tags=["subdomain-auth"])


def _is_rfc1918(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(cidr) for cidr in cidrs)
    except ValueError:
        return False


def _resolve_app_by_host(db: Session, host: str) -> Optional[App]:
    """Resolve App for this Host header.

    Strategy: app slug = first label of FQDN (e.g. transfer.ar-systems.fr -> transfer).

    TODO Phase 4: add explicit `fqdn` field on App.
    """
    slug = host.split(".")[0] if host else ""
    return (
        db.query(App)
        .filter(App.slug == slug, App.enabled == True)  # noqa: E712
        .first()
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
        Cookie            — client cookies (oauth2-proxy session)

    Decision flow:
        1. RFC1918 bypass       -> 200 immediately (LAN access without SSO)
        2. App resolution       -> 401 if no app for this Host
        3. oauth2-proxy session -> proxy to oauth2-proxy /oauth2/auth
        4. TODO Phase 4: RBAC Keycloak groups vs app.groups
    """
    original_host = request.headers.get("X-Original-Host", "")
    client_ip = request.headers.get("X-Real-IP", "")
    cookie_header = request.headers.get("Cookie", "")

    # 1. RFC1918 bypass
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

    # 3. oauth2-proxy session check (same logic as auth.py)
    # TODO Phase 4: RealmConfig DB lookup for per-realm oauth2-proxy URL
    proxy_url = settings.oauth2_proxy_default_url

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{proxy_url}/oauth2/auth",
                headers={"Cookie": cookie_header},
            )
    except httpx.RequestError:
        return Response(status_code=503)

    if resp.status_code != 200:
        return Response(status_code=401)

    # 4. TODO Phase 4: RBAC group check vs app.groups
    # Phase 3: valid session + known app = access granted
    x_auth_user = resp.headers.get("X-Auth-User", "")
    return Response(
        status_code=200,
        headers={
            "X-Auth-Source": "oidc",
            "X-Auth-User": x_auth_user,
            "X-Auth-App": app.slug,
        },
    )
