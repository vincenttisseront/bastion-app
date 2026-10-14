"""Portal session cookies (``bastion_session``, ``bg_session``) set and cleared alike.

Both live on the portal parent domain so subdomain ``auth_request`` receives
them. A delete must repeat the exact flags used at set time, otherwise browsers
keep the ``Secure`` cookie alive.
"""

from __future__ import annotations

from fastapi import Response

from app.robotic.robotic_session_cookies import portal_sso_cookie_domain
from app.sso_settings import Settings

_COOKIE_FLAGS = {"httponly": True, "secure": True, "samesite": "lax", "path": "/"}


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
