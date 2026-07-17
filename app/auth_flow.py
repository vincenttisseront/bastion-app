"""Login state machine helpers — IdP vs break-glass setup."""

from urllib.parse import quote

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import RealmConfig


def get_default_idp_realm(db: Session) -> RealmConfig | None:
    """Return the active default IdP realm, if configured."""
    return db.query(RealmConfig).filter_by(is_default=True, enabled=True).first()


def resolve_rd(request: Request, default: str = "/apps") -> str:
    """Extract a safe relative redirect target from the query string."""
    rd = request.query_params.get("rd") or default
    if not isinstance(rd, str) or not rd.startswith("/") or rd.startswith("//"):
        return default
    return rd


def oauth2_start_url(realm_slug: str, rd: str) -> str:
    return f"/oauth2/{realm_slug}/start?rd={quote(rd, safe='')}"


def setup_url(rd: str) -> str:
    return f"/auth/setup?rd={quote(rd, safe='')}"
