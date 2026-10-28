"""Portal session cookies (``bastion_session``, ``bg_session``) set and cleared alike.

Both live on the portal parent domain so subdomain ``auth_request`` receives
them. A delete must repeat the exact flags used at set time, otherwise browsers
keep the ``Secure`` cookie alive.

Also clears oauth2-proxy session cookies (``_oauth2_proxy*``) with the same
parent Domain so ``GET /logout`` does not leave a lingering SSO cookie that
nginx still honours via ``auth_request``.

``GET /logout`` leaves ``_oauth2_proxy`` intact on the first hop and redirects
to ``/oauth2/{realm}/sign_out`` so oauth2-proxy can clear its cookie and hit
the IdP ``end_session`` endpoint when configured.
"""

from __future__ import annotations

from urllib.parse import quote

from fastapi import Response

from app.robotic.robotic_session_cookies import portal_sso_cookie_domain
from app.sso_settings import Settings

_COOKIE_FLAGS = {"httponly": True, "secure": True, "samesite": "lax", "path": "/"}

# oauth2-proxy v7 with cookie_secure=true (see generate_oauth2_proxy_config).
# Also clear dotted Domain= form (.example.com) used in cookie_domains.
OAUTH2_PROXY_COOKIE_NAMES = (
    "_oauth2_proxy",
    "_oauth2_proxy_csrf",
)

_DEFAULT_POST_LOGOUT_RD = "/auth/login"


def set_portal_cookie(
    response: Response,
    name: str,
    value: str,
    *,
    max_age: int,
    settings: Settings,
) -> None:
    domain = portal_sso_cookie_domain(settings.portal_domain or "")
    extra = {"domain": domain} if domain else {}
    response.set_cookie(key=name, value=value, max_age=max_age, **_COOKIE_FLAGS, **extra)


def clear_portal_cookie(response: Response, name: str, settings: Settings | None) -> None:
    """Clear the parent-domain cookie and any legacy host-only copy."""
    response.delete_cookie(key=name, **_COOKIE_FLAGS)
    domain = portal_sso_cookie_domain(settings.portal_domain or "") if settings else None
    if domain:
        response.delete_cookie(key=name, **_COOKIE_FLAGS, domain=domain)


def clear_oauth2_proxy_cookies(
    response: Response, settings: Settings | None
) -> None:
    """Expire oauth2-proxy session + CSRF cookies (host-only and parent Domain).

    oauth2-proxy sets ``cookie_domains = [.parent]`` when the portal FQDN has a
    parent; browsers may store Domain=parent or Domain=.parent depending on
    version — clear both shapes plus host-only leftovers.
    """
    domain = portal_sso_cookie_domain(settings.portal_domain or "") if settings else None
    domains: list[str | None] = [None]
    if domain:
        domains.append(domain)
        if not domain.startswith("."):
            domains.append(f".{domain}")
    for name in OAUTH2_PROXY_COOKIE_NAMES:
        for d in domains:
            if d:
                response.delete_cookie(key=name, **_COOKIE_FLAGS, domain=d)
            else:
                response.delete_cookie(key=name, **_COOKIE_FLAGS)


def clear_browser_auth_cookies(
    response: Response,
    settings: Settings | None,
    *,
    include_oauth2: bool = True,
) -> None:
    """Clear browser-side portal auth cookies (SSO stacks + admin MFA).

    Does not revoke DB jtits — callers still call revoke helpers when a request
    cookie is present.

    Set ``include_oauth2=False`` when the next hop is oauth2-proxy
    ``/oauth2/.../sign_out`` so the proxy still sees its session cookie and can
    invoke the IdP end-session endpoint.
    """
    from app.auth.breakglass import COOKIE_NAME as BG_COOKIE
    from app.auth.mfa_cookie import clear_mfa_ok_cookie
    from app.auth.webauthn_service import clear_challenge_cookie

    cookie_name = "bastion_session"
    if settings is not None:
        cookie_name = (
            getattr(settings, "oidc_session_cookie_name", None) or cookie_name
        ).strip() or cookie_name
    clear_portal_cookie(response, cookie_name, settings)
    clear_portal_cookie(response, BG_COOKIE, settings)
    if include_oauth2:
        clear_oauth2_proxy_cookies(response, settings)
    clear_mfa_ok_cookie(response)
    clear_challenge_cookie(response)


def oauth2_sign_out_path(
    realm_slug: str,
    *,
    rd: str = _DEFAULT_POST_LOGOUT_RD,
) -> str:
    """Browser path for oauth2-proxy logout (clears cookie + optional IdP logout)."""
    raw_slug = (realm_slug or "").strip() or "default"
    # Realm path segment: alnum + hyphen/underscore only (no traversal).
    slug = "".join(c for c in raw_slug if c.isalnum() or c in "-_") or "default"
    target = (rd or _DEFAULT_POST_LOGOUT_RD).strip() or _DEFAULT_POST_LOGOUT_RD
    if not target.startswith("/") or target.startswith("//"):
        target = _DEFAULT_POST_LOGOUT_RD
    return f"/oauth2/{slug}/sign_out?rd={quote(target, safe='/?&=')}"


def resolve_logout_realm_slug(request, settings: Settings, db=None) -> str:
    """Best-effort realm for ``/oauth2/{slug}/sign_out`` from native session or default."""
    default = (settings.sso_portal_default_realm_slug or "default").strip() or "default"
    header = (request.headers.get("x-portal-realm-slug") or "").strip()
    cookie_name = (settings.oidc_session_cookie_name or "bastion_session").strip()
    raw = (request.cookies.get(cookie_name) or "").strip()
    if raw and db is not None:
        try:
            from app.auth.oidc_bff import realm_slug_from_oidc_cookie

            realm = realm_slug_from_oidc_cookie(raw, db, settings)
            if realm:
                return realm
        except Exception:
            pass
    return header or default
