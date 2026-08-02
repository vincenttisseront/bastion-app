"""Login state machine helpers — IdP vs break-glass setup."""

from urllib.parse import quote, urlparse

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import RealmConfig
from app.robotic.robotic_session_cookies import shared_parent_domain


def get_default_idp_realm(db: Session) -> RealmConfig | None:
    """Return the active default IdP realm, if configured."""
    return db.query(RealmConfig).filter_by(is_default=True, enabled=True).first()


def safe_post_login_rd(
    rd: str | None,
    *,
    portal_domain: str = "",
    default: str = "/apps",
) -> str:
    """
    Sanitize ``rd`` after login / SSO return.

    Allows relative paths and absolute ``https://`` URLs whose host shares a
    parent domain with the portal (subdomain app return after auth_request 401).
    """
    value = (rd or "").strip() or default
    if value.startswith("/") and not value.startswith("//"):
        if value in ("/dashboard", "/admin/dashboard"):
            return default
        return value
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        return default
    if shared_parent_domain(parsed.hostname, portal_domain or "") is None:
        return default
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"https://{parsed.hostname.lower()}{path}{query}"


def resolve_rd(
    request: Request,
    default: str = "/apps",
    *,
    portal_domain: str = "",
) -> str:
    """Extract a safe redirect target from the query string.

    /dashboard is admin-only; unauthenticated hits there would bake rd=/dashboard
    into the OIDC state and land end-users on a 403 bounce. Prefer /apps.
    Absolute https rd= is allowed when the host shares the portal parent domain
    (subdomain ``@portal_redirect`` → ``/login?rd=https://app…/``).
    """
    return safe_post_login_rd(
        request.query_params.get("rd"),
        portal_domain=portal_domain,
        default=default,
    )


def oauth2_start_url(realm_slug: str, rd: str) -> str:
    return f"/oauth2/{realm_slug}/start?rd={quote(rd, safe='')}"


def setup_url(rd: str) -> str:
    return f"/auth/setup?rd={quote(rd, safe='')}"
