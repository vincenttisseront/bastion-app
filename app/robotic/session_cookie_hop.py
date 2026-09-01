"""Generic session-cookie hop — host-only target cookies on the app FQDN.

Portal responses cannot set host-only cookies for ``https://{app-fqdn}/`` (browsers
reject foreign host-only Set-Cookie). For ``injected_cookie_scope=host_only`` in
subdomain mode the portal seals cookie values into a short-lived hop cookie
(``Domain=<parent>``), redirects to ``https://{fqdn}/.bastion/session-cookies``,
and nginx proxies that path to this endpoint which sets the real session cookies
**without** Domain (host-only on the app host).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Any
from urllib.parse import quote, urlencode, urlparse

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse

from app.robotic.robotic_session_cookies import (
    COOKIE_SCOPE_HOST_ONLY,
    cookie_should_be_httponly,
    shared_parent_domain,
)
from app.sso_settings import Settings, get_settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["session-cookie-hop"])

HOP_COOKIE_NAME = "bastion_session_hop"
# Accepted when reading (migration from CrushFTP-named hop).
_LEGACY_HOP_COOKIE_NAMES = (HOP_COOKIE_NAME, "bastion_crush_hop")

HOP_PATH = "/.bastion/session-cookies"
SSO_MIRROR_PATH = "/.bastion/sso-session-mirror"
# Keep old path so transfer nginx configs already deployed still work.
_LEGACY_HOP_PATHS = ("/.bastion/crush-session",)

HOP_TTL_SECONDS = 60
DEFAULT_NEXT = "/"


def _hop_secret(settings: Settings) -> bytes:
    from app.runtime_secrets_service import resolve_session_hop_secret

    raw = resolve_session_hop_secret(settings).strip()
    if not raw:
        # Never fall back to a literal like "dev" or the vault internal token.
        raise RuntimeError(
            "SESSION_HOP_SECRET is required to seal session-cookie hop payloads"
        )
    return hashlib.sha256(f"session-cookie-hop:{raw}".encode()).digest()


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def seal_session_hop_payload(
    *,
    cookies: dict[str, str],
    target_url: str,
    slug: str,
    settings: Settings,
    ttl_seconds: int = HOP_TTL_SECONDS,
) -> str:
    """Return signed payload for the hop cookie value (any target session cookies)."""
    body = {
        "c": {k: v for k, v in cookies.items() if v},
        "n": target_url,
        "s": slug,
        "e": int(time.time()) + int(ttl_seconds),
    }
    payload = _b64url_encode(
        json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    )
    sig = hmac.new(_hop_secret(settings), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def unseal_session_hop_payload(
    token: str, settings: Settings
) -> tuple[dict[str, Any] | None, str]:
    """Return ``(body, reason)`` — reason is empty on success."""
    if not token or "." not in token:
        return None, "missing_hop_cookie"
    payload, _, sig = token.partition(".")
    if not payload or not sig:
        return None, "malformed_token"
    try:
        expected = hmac.new(
            _hop_secret(settings), payload.encode(), hashlib.sha256
        ).hexdigest()
    except RuntimeError:
        return None, "hop_secret_unavailable"
    if not hmac.compare_digest(expected, sig):
        return None, "bad_signature"
    try:
        body = json.loads(_b64url_decode(payload))
    except (ValueError, json.JSONDecodeError):
        return None, "bad_payload"
    if not isinstance(body, dict):
        return None, "bad_payload"
    exp = body.get("e")
    if not isinstance(exp, int) or exp < int(time.time()):
        return None, "expired"
    cookies = body.get("c")
    if not isinstance(cookies, dict) or not cookies:
        return None, "empty_cookies"
    return body, ""


def session_hop_url(fqdn: str, *, next_path: str | None = None) -> str:
    host = (fqdn or "").strip().rstrip("/")
    if host.startswith("https://") or host.startswith("http://"):
        base = host
    else:
        base = f"https://{host}"
    query = urlencode({"next": next_path}) if next_path else ""
    url = f"{base}{HOP_PATH}"
    return f"{url}?{query}" if query else url


def _safe_next(candidate: str | None, fallback: str) -> str:
    raw = (candidate or "").strip() or fallback
    parsed = urlparse(raw)
    if parsed.scheme or parsed.netloc:
        path = parsed.path or DEFAULT_NEXT
        if not path.startswith("/"):
            return DEFAULT_NEXT
        return path + (f"?{parsed.query}" if parsed.query else "")
    if not raw.startswith("/"):
        return DEFAULT_NEXT
    return raw


def _absolute_app_url(request: Request, path: str) -> str:
    """Build https://{app-fqdn}{path} from nginx X-Forwarded-Host (hop proxy)."""
    host = (
        (request.headers.get("x-forwarded-host") or request.headers.get("host") or "")
        .split(",")[0]
        .strip()
        .split(":")[0]
    )
    if not host:
        return path
    path = path if path.startswith("/") else f"/{path}"
    return f"https://{host}{path}"


def _portal_apps_url(settings: Settings) -> str:
    portal = (settings.portal_domain or "").strip().rstrip("/")
    if not portal:
        return "/apps"
    if portal.startswith("https://") or portal.startswith("http://"):
        return f"{portal.rstrip('/')}/apps"
    return f"https://{portal}/apps"


def attach_session_hop_portal_cookies(
    response: Response,
    *,
    cookies: dict[str, str],
    target_url: str,
    slug: str,
    fqdn: str,
    settings: Settings,
) -> None:
    """
    From the portal: stash sealed target cookies, clear any stuck parent-domain
    copies of those names, so the hop on ``fqdn`` can set host-only cookies.
    """
    portal = settings.portal_domain or ""
    shared = shared_parent_domain(fqdn, portal)
    sealed = seal_session_hop_payload(
        cookies=cookies,
        target_url=target_url,
        slug=slug,
        settings=settings,
    )
    hop_kwargs: dict = {
        "key": HOP_COOKIE_NAME,
        "value": sealed,
        "path": "/",
        "max_age": HOP_TTL_SECONDS,
        "httponly": True,
        "secure": True,
        "samesite": "lax",
    }
    if shared:
        hop_kwargs["domain"] = shared
    response.set_cookie(**hop_kwargs)

    for key in cookies:
        if not cookies.get(key):
            continue
        # __Secure-/__Host- cookies must not carry a Domain attribute (browsers reject).
        if key.startswith("__Secure-") or key.startswith("__Host-"):
            continue
        clear_kwargs: dict = {
            "key": key,
            "value": "",
            "path": "/",
            "max_age": 0,
            "httponly": cookie_should_be_httponly(key),
            "secure": True,
            "samesite": "lax",
        }
        if shared:
            clear_kwargs["domain"] = shared
        response.set_cookie(**clear_kwargs)


def apply_host_only_bastion_session_mirror(
    response: Response,
    request: Request,
    settings: Settings,
) -> bool:
    """Host-only copy of bastion_session on the app FQDN (parent Domain may not stick)."""
    from app.auth import extract_oidc_session_cookie_raw

    raw = extract_oidc_session_cookie_raw(request, settings)
    if not raw:
        return False
    name = (settings.oidc_session_cookie_name or "").strip() or "bastion_session"
    response.set_cookie(
        key=name,
        value=raw,
        max_age=settings.oidc_session_max_age,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )
    return True


def redirect_via_subdomain_sso_mirror(rd: str, *, portal_domain: str) -> str:
    """Send post-login redirects through /.bastion/sso-session-mirror on the app host."""
    parsed = urlparse((rd or "").strip())
    portal = (portal_domain or "").strip().lower()
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in ("https", "http") or not host or host == portal:
        return rd
    path = (parsed.path or "").rstrip("/")
    if path == SSO_MIRROR_PATH.rstrip("/"):
        return rd
    next_path = parsed.path or "/"
    if parsed.query:
        next_path = f"{next_path}?{parsed.query}"
    return (
        f"https://{host}{SSO_MIRROR_PATH}?next={quote(next_path, safe='')}"
    )


def apply_host_only_session_cookies(
    response: Response,
    cookies: dict[str, str],
    *,
    shared_parent: str | None,
    expire_cookie_names: tuple[str, ...] | None = None,
) -> None:
    """Set target session cookies host-only; expire parent-domain copies + hop cookie."""
    expire_names = list(expire_cookie_names or ())
    if "__Host-session" in cookies or "__Secure-session" in cookies:
        from app.bastion.drivers.teleport import stale_teleport_browser_cookies

        expire_names.extend(stale_teleport_browser_cookies())

    for key, value in cookies.items():
        if not value:
            continue
        samesite = "none" if "csrf" in key.lower() else "lax"
        response.set_cookie(
            key=key,
            value=value,
            path="/",
            httponly=cookie_should_be_httponly(key),
            secure=True,
            samesite=samesite,
        )
    for stale in dict.fromkeys(expire_names):
        if stale in cookies:
            continue
        response.set_cookie(
            key=stale,
            value="",
            path="/",
            max_age=0,
            httponly=True,
            secure=True,
            samesite="lax",
        )
    if shared_parent:
        for key in cookies:
            if key.startswith("__Secure-") or key.startswith("__Host-"):
                continue
            response.set_cookie(
                key=key,
                value="",
                path="/",
                domain=shared_parent,
                max_age=0,
                httponly=cookie_should_be_httponly(key),
                secure=True,
                samesite="lax",
            )
    for hop_name in _LEGACY_HOP_COOKIE_NAMES:
        clear_hop: dict = {
            "key": hop_name,
            "value": "",
            "path": "/",
            "max_age": 0,
            "httponly": True,
            "secure": True,
            "samesite": "lax",
        }
        if shared_parent:
            clear_hop["domain"] = shared_parent
        response.set_cookie(**clear_hop)


def _read_hop_token(request: Request) -> str:
    for name in _LEGACY_HOP_COOKIE_NAMES:
        value = request.cookies.get(name) or ""
        if value:
            return value
    return ""


def _hop_handler(
    request: Request,
    settings: Settings,
    next: str | None,  # noqa: A002
):
    token = _read_hop_token(request)
    body, reason = unseal_session_hop_payload(token, settings)
    if body is None:
        logger.warning(
            "session cookie hop rejected reason=%s has_cookie=%s host=%s xf_host=%s",
            reason,
            bool(token),
            request.headers.get("host"),
            request.headers.get("x-forwarded-host"),
        )
        # Never bounce to bare "/" on the portal Host — send the user back to catalogue.
        return RedirectResponse(url=_portal_apps_url(settings), status_code=302)

    target_path = _safe_next(next or body.get("n"), body.get("n") or DEFAULT_NEXT)
    cookies = {k: str(v) for k, v in (body.get("c") or {}).items() if v}
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
    shared = shared_parent_domain(host.split(":")[0], settings.portal_domain or "")
    # Prefer absolute URL on the app FQDN (sealed n may be https://fqdn/).
    sealed_next = (body.get("n") or "").strip()
    if sealed_next.startswith("https://") or sealed_next.startswith("http://"):
        target = sealed_next
    else:
        target = _absolute_app_url(request, target_path)

    logger.info(
        "session cookie hop ok slug=%s cookies=%s target=%s host=%s",
        body.get("s"),
        sorted(cookies.keys()),
        target,
        host,
    )
    response = RedirectResponse(url=target, status_code=302)
    apply_host_only_session_cookies(response, cookies, shared_parent=shared)
    apply_host_only_bastion_session_mirror(response, request, settings)
    return response


@router.get(SSO_MIRROR_PATH)
@router.get("/api/internal/sso-session-mirror")
def sso_session_mirror(
    request: Request,
    settings: Settings = Depends(get_settings),
    next: str | None = None,  # noqa: A002
):
    """Public — host-only bastion_session after portal SSO before SPA API calls."""
    target = _absolute_app_url(request, _safe_next(next, DEFAULT_NEXT))
    response = RedirectResponse(url=target, status_code=302)
    apply_host_only_bastion_session_mirror(response, request, settings)
    return response


@router.get(HOP_PATH)
@router.get("/api/internal/session-cookie-hop")
def session_cookie_hop(
    request: Request,
    settings: Settings = Depends(get_settings),
    next: str | None = None,  # noqa: A002
):
    """Public (token-in-cookie). Must be reached on the app FQDN via nginx proxy."""
    return _hop_handler(request, settings, next)


@router.get("/.bastion/crush-session")
@router.get("/api/internal/crush-cookie-hop")
def session_cookie_hop_legacy_alias(
    request: Request,
    settings: Settings = Depends(get_settings),
    next: str | None = None,  # noqa: A002
):
    """Compatibility aliases for the first CrushFTP-named hop deploy."""
    return _hop_handler(request, settings, next)


# Re-export scope constant for callers
__all__ = [
    "COOKIE_SCOPE_HOST_ONLY",
    "HOP_COOKIE_NAME",
    "HOP_PATH",
    "SSO_MIRROR_PATH",
    "apply_host_only_bastion_session_mirror",
    "redirect_via_subdomain_sso_mirror",
    "attach_session_hop_portal_cookies",
    "apply_host_only_session_cookies",
    "router",
    "seal_session_hop_payload",
    "session_hop_url",
    "unseal_session_hop_payload",
]
