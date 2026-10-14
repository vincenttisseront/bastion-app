"""Single realm-by-slug lookup (case-insensitive, never a LIKE pattern)."""

from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import RealmConfig


def find_realm(db: Session, slug: str | None) -> RealmConfig | None:
    """Return the realm whose slug equals ``slug`` ignoring case.

    Callers must use ``realm.slug`` afterwards: user input such as ``%`` or a
    differently-cased slug must never reach a token or a header.
    """
    wanted = (slug or "").strip()
    if not wanted:
        return None
    exact = db.query(RealmConfig).filter(RealmConfig.slug == wanted).first()
    if exact is not None:
        return exact
    return (
        db.query(RealmConfig)
        .filter(func.lower(RealmConfig.slug) == wanted.lower())
        .first()
    )
