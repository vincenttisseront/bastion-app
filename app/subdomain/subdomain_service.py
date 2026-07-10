"""Subdomain SSO helpers — app resolution and RBAC (Phase 4)."""

from typing import Optional

from sqlalchemy.orm import Session

from app.models import App, AppGroup, RBACGroup


def get_app_by_slug(db: Session, slug: str) -> Optional[App]:
    return db.query(App).filter(App.slug == slug, App.enabled == True).first()  # noqa: E712


def get_app_allowed_groups(db: Session, app_id: int) -> list[str]:
    """Return RBAC group names authorized for this app."""
    rows = (
        db.query(RBACGroup.name)
        .join(AppGroup, AppGroup.group_id == RBACGroup.id)
        .filter(AppGroup.app_id == app_id)
        .all()
    )
    return [r.name for r in rows]


def user_has_access(user_groups: list[str], app_groups: list[str]) -> bool:
    """Check if user belongs to at least one authorized group.

    If app_groups is empty: open access (no restriction configured).
    """
    if not app_groups:
        return True
    return bool(set(user_groups) & set(app_groups))
