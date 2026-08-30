"""Subdomain SSO helpers — app resolution."""

from typing import Optional

from sqlalchemy.orm import Session

from app.models import App


def get_app_by_slug(db: Session, slug: str) -> Optional[App]:
    return db.query(App).filter(App.slug == slug, App.enabled == True).first()  # noqa: E712
