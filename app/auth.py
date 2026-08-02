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
    process_breakglass_auth_request,
)
from app.database import get_db
from app.models import RealmConfig
from app.request_client_ip import client_ip_from_request
from app.security.session_binding_service import evaluate_sso_binding
from app.sso_settings import Settings, get_settings

router = APIRouter()

# Nginx auth_request_set (vhost_sso_portal.conf.j2) reads only these upstream headers:
#   $upstream_http_x_auth_request_user
#   $upstream_http_x_auth_request_email
#   $upstream_http_x_auth_request_groups
#   $upstream_http_x_auth_request_preferred_username
# Whitelist by prefix — never relay Set-Cookie or other oauth2-proxy headers.
# Native bastion_session must emit the same set (incl. groups) for AccessGrant parity.
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


def _cookie_value_from_header(cookie_header: str, name: str) -> str | None:
    """Parse ``name=value`` from a raw Cookie header (last match wins)."""
    if not cookie_header or not name:
        return None
    prefix = f"{name}="
    found: str | None = None
    for part in cookie_header.split(";"):
        piece = part.strip()
        if piece.startswith(prefix):
            found = piece[len(prefix) :].strip() or None
    return found


def iter_oidc_session_cookie_candidates(
    request: Request,
    settings: Settings,
) -> list[str]:
    """
    All distinct bastion_session JWT candidates from an auth_request / login.

    Order matters for the first non-empty peek (``extract_oidc_session_cookie_raw``),
    but ``_native_oidc_auth_response`` validates each until one succeeds — a
    garbled Starlette parse must not hide a good ``X-Bastion-Session-Cookie``
    or raw Cookie value (HAR transfer loop after CrushFTP Cookie filtering).
    """
    cookie_name = (settings.oidc_session_cookie_name or "").strip() or "bastion_session"
    ordered: list[str] = []
    seen: set[str] = set()

    def _add(value: str | None) -> None:
        raw = (value or "").strip()
        if not raw or raw in seen:
            return
        seen.add(raw)
        ordered.append(raw)

    # Explicit nginx header first — set from $cookie_bastion_session at rewrite
    # time (server-level set) so CrushFTP location / Cookie rewrites cannot
    # starve the auth subrequest.
    _add(
        request.headers.get("X-Bastion-Session-Cookie")
        or request.headers.get("x-bastion-session-cookie")
    )
    _add(request.cookies.get(cookie_name))
    _add(_cookie_value_from_header(request.headers.get("Cookie") or "", cookie_name))
    return ordered


def extract_oidc_session_cookie_raw(
    request: Request,
    settings: Settings,
) -> str | None:
    """
    Resolve native session JWT from the auth_request (first non-empty candidate).

    Prefer nginx ``X-Bastion-Session-Cookie``, then Starlette's cookie jar, then
    raw Cookie header parsing.
    """
    candidates = iter_oidc_session_cookie_candidates(request, settings)
    return candidates[0] if candidates else None


def _native_oidc_auth_response(
    request: Request,
    settings: Settings,
    db: Session,
) -> Response | None:
    """
    Accept native ``bastion_session`` when the cookie's realm is pilot-enabled.

    Returns a 200 Response with X-Auth-Request-* headers, or None to fall through
    to the oauth2-proxy path (cookie absent, invalid, revoked, or realm not enabled).
    """
    from app.oidc_bff import validate_oidc_session_cookie
    from app.oidc_native_session import is_oidc_native_session_enabled_for_realm

    claims = None
    for raw in iter_oidc_session_cookie_candidates(request, settings):
        claims = validate_oidc_session_cookie(raw, db=db, settings=settings)
        if claims is None:
            continue
        if not is_oidc_native_session_enabled_for_realm(db, claims.realm, settings):
            claims = None
            continue
        break
    if claims is None:
        return None

    headers: dict[str, str] = {
        "X-Auth-Request-User": claims.sub,
    }
    username = (claims.username or "").strip()
    email = (claims.email or "").strip()
    if username:
        headers["X-Auth-Request-Preferred-Username"] = username
    if email:
        headers["X-Auth-Request-Email"] = email
    elif username and "@" in username:
        headers["X-Auth-Request-Email"] = username
    if claims.groups:
        headers["X-Auth-Request-Groups"] = ",".join(claims.groups)
    return Response(status_code=200, headers=headers)


async def _oauth2_proxy_auth_response(
    request: Request,
    settings: Settings,
    db: Session,
) -> Response | None:
    """Call oauth2-proxy /oauth2/auth. None if no IdP; else proxy status (202/401/503)."""
    from app.database import release_db_connection

    default_realm = get_default_idp_realm(db)
    if not default_realm:
        return None

    realm_slug = request.headers.get("X-Realm-Slug", default_realm.slug)
    proxy_url = get_realm_proxy_url(realm_slug, settings, db)
    cookie_header = request.headers.get("Cookie", "")
    # Portal auth_request is hot — release pool slot before outbound HTTP.
    release_db_connection(db)
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

    Intentionally does **not** enforce per-app AccessGrant: the generic portal
    launcher (``/apps``) must stay reachable for any authenticated user.
    FastAPI ``GET /dashboard`` is separate and remains ``require_admin``.
    Application URL enforcement lives in ``/internal/subdomain-auth``.
    """
    # Do NOT apply RFC1918 bypass here. Behind Traefik/vpcbr, X-Real-IP is often
    # 10.5.0.0/16 — a bypass would return 200 with no identity and break SSO
    # (auth OK → portal 401 → /auth/login loop). LAN recovery = break-glass.

    # Progressive cutover: native bastion_session before oauth2-proxy (flag-gated).
    native = _native_oidc_auth_response(request, settings, db)
    if native is not None:
        return native

    # Prefer SSO session over break-glass when both cookies are present.
    # Otherwise a leftover bg_session sends /apps → 302 /dashboard and never hits oauth2.
    oauth2_resp = await _oauth2_proxy_auth_response(request, settings, db)
    if oauth2_resp is not None and oauth2_resp.status_code in (200, 202):
        from app.web.user_context import _human_label, looks_like_uuid

        email = oauth2_resp.headers.get("X-Auth-Request-Email") or ""
        preferred = (
            oauth2_resp.headers.get("X-Auth-Request-Preferred-Username") or ""
        )
        x_user = oauth2_resp.headers.get("X-Auth-Request-User") or ""
        readable = _human_label(email, preferred)
        kc_id = x_user.strip() if looks_like_uuid(x_user) else None
        username = readable or (
            None if looks_like_uuid(x_user) else (x_user.strip() or None)
        )
        try:
            evaluate_sso_binding(
                db,
                request,
                username=username,
                keycloak_user_id=kc_id,
            )
            db.commit()
        except Exception:
            db.rollback()
        return oauth2_resp

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
        return Response(status_code=200, headers={"X-Auth-Source": "breakglass"})

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
