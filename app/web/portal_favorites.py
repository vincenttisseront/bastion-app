"""Portal Accès rapides — per-user app favorites (pins)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import App, UserAppFavorite, utcnow


class FavoriteError(RuntimeError):
    """Favorite add/remove refused."""


def list_favorite_app_ids(db: Session, keycloak_user_id: str | None) -> list[int]:
    """Return pinned application ids for the user, oldest pin first."""
    kid = (keycloak_user_id or "").strip()
    if not kid:
        return []
    rows = (
        db.query(UserAppFavorite.application_id)
        .filter(UserAppFavorite.keycloak_user_id == kid)
        .order_by(UserAppFavorite.created_at.asc(), UserAppFavorite.id.asc())
        .all()
    )
    return [int(r[0]) for r in rows]


def add_favorite(
    db: Session,
    *,
    keycloak_user_id: str | None,
    application_id: int,
    actor: str,
    ip_address: str | None = None,
) -> bool:
    """
    Pin an app. Returns True if created, False if already pinned.
    Caller must have verified the user may access the app.
    """
    kid = (keycloak_user_id or "").strip()
    if not kid:
        raise FavoriteError("Identité utilisateur requise pour les Accès rapides")
    app = db.query(App).filter_by(id=application_id).first()
    if app is None:
        raise FavoriteError("Application introuvable")

    existing = (
        db.query(UserAppFavorite)
        .filter_by(keycloak_user_id=kid, application_id=application_id)
        .first()
    )
    if existing is not None:
        return False

    db.add(
        UserAppFavorite(
            keycloak_user_id=kid,
            application_id=application_id,
            created_at=utcnow(),
        )
    )
    db.commit()
    log_action(
        db,
        actor=actor,
        action="portal.favorite_add",
        target=app.slug,
        details={"application_id": application_id},
        ip_address=ip_address,
    )
    return True


def remove_favorite(
    db: Session,
    *,
    keycloak_user_id: str | None,
    application_id: int,
    actor: str,
    ip_address: str | None = None,
) -> bool:
    """Unpin an app. Returns True if a row was deleted."""
    kid = (keycloak_user_id or "").strip()
    if not kid:
        raise FavoriteError("Identité utilisateur requise pour les Accès rapides")
    app = db.query(App).filter_by(id=application_id).first()
    row = (
        db.query(UserAppFavorite)
        .filter_by(keycloak_user_id=kid, application_id=application_id)
        .first()
    )
    if row is None:
        return False
    db.delete(row)
    db.commit()
    log_action(
        db,
        actor=actor,
        action="portal.favorite_remove",
        target=(app.slug if app else str(application_id)),
        details={"application_id": application_id},
        ip_address=ip_address,
    )
    return True
