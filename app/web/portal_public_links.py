"""Portal « Mes liens » — pin managed-domain public_proxy apps on the profile."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.access_modes import app_launch_url, normalize_access_mode
from app.audit import log_action
from app.bastion.nginx_public_proxy_export import iter_public_proxy_apps
from app.bastion.pending_host_service import (
    hostname_is_managed,
    managed_domain_suffixes,
)
from app.models import App, UserPublicAppLink, utcnow
from app.portal_settings_service import ensure_portal_settings
from app.setup_wizard_service import get_effective_portal_domain
from app.sso_settings import Settings
from app.web.app_logos import logo_public_url


class PublicLinkError(RuntimeError):
    """Personal public-proxy link add/remove refused."""


def _managed_suffixes(db: Session, settings: Settings) -> list[str]:
    portal_row = ensure_portal_settings(db, settings)
    portal_domain = get_effective_portal_domain(db, settings)
    return managed_domain_suffixes(
        portal_domain=portal_domain,
        extra_raw=getattr(portal_row, "managed_domain_suffixes", None),
    )


def is_linkable_public_proxy(
    app: App,
    *,
    suffixes: list[str],
) -> bool:
    """True for enabled public_proxy apps whose FQDN is under managed domains."""
    if not getattr(app, "enabled", True):
        return False
    if normalize_access_mode(app.access_mode) != "public_proxy":
        return False
    fqdn = (app.public_fqdn or "").strip()
    if not fqdn:
        return False
    return hostname_is_managed(fqdn, suffixes)


def list_eligible_public_proxy_apps(db: Session, settings: Settings) -> list[App]:
    """Enabled public_proxy apps on managed domain suffixes (alphabetical)."""
    suffixes = _managed_suffixes(db, settings)
    if not suffixes:
        return []
    return [
        app
        for app in iter_public_proxy_apps(db)
        if is_linkable_public_proxy(app, suffixes=suffixes)
    ]


def list_linked_app_ids(db: Session, keycloak_user_id: str | None) -> list[int]:
    """Return pinned public-proxy application ids, oldest pin first."""
    kid = (keycloak_user_id or "").strip()
    if not kid:
        return []
    rows = (
        db.query(UserPublicAppLink.application_id)
        .filter(UserPublicAppLink.keycloak_user_id == kid)
        .order_by(UserPublicAppLink.created_at.asc(), UserPublicAppLink.id.asc())
        .all()
    )
    return [int(r[0]) for r in rows]


def serialize_public_link_tile(app: App, *, is_linked: bool) -> dict:
    fqdn = (app.public_fqdn or "").strip()
    return {
        "id": app.id,
        "slug": app.slug,
        "label": app.label,
        "description": app.description or "",
        "public_fqdn": fqdn,
        "launch_url": app_launch_url(app),
        "logo_url": logo_public_url(app),
        "is_linked": is_linked,
    }


def profile_public_link_tiles(
    db: Session,
    settings: Settings,
    *,
    keycloak_user_id: str | None,
) -> tuple[list[dict], list[dict]]:
    """Return ``(linked_tiles, available_tiles)`` for Mon profil → Mes liens."""
    eligible = list_eligible_public_proxy_apps(db, settings)
    linked_ids = list_linked_app_ids(db, keycloak_user_id)
    linked_set = set(linked_ids)
    by_id = {app.id: app for app in eligible}

    linked: list[dict] = []
    for app_id in linked_ids:
        app = by_id.get(app_id)
        if app is None:
            continue
        linked.append(serialize_public_link_tile(app, is_linked=True))

    available: list[dict] = [
        serialize_public_link_tile(app, is_linked=False)
        for app in eligible
        if app.id not in linked_set
    ]
    return linked, available


def _require_eligible_app(
    db: Session,
    settings: Settings,
    application_id: int,
) -> App:
    app = db.query(App).filter_by(id=application_id).first()
    if app is None:
        raise PublicLinkError("Application introuvable")
    suffixes = _managed_suffixes(db, settings)
    if not is_linkable_public_proxy(app, suffixes=suffixes):
        raise PublicLinkError(
            "Seuls les proxy publics sur un domaine géré peuvent être ajoutés"
        )
    return app


def add_public_link(
    db: Session,
    settings: Settings,
    *,
    keycloak_user_id: str | None,
    application_id: int,
    actor: str,
    ip_address: str | None = None,
) -> bool:
    """Pin a managed public_proxy app. Returns True if created."""
    kid = (keycloak_user_id or "").strip()
    if not kid:
        raise PublicLinkError("Identité utilisateur requise pour Mes liens")
    app = _require_eligible_app(db, settings, application_id)

    existing = (
        db.query(UserPublicAppLink)
        .filter_by(keycloak_user_id=kid, application_id=application_id)
        .first()
    )
    if existing is not None:
        return False

    db.add(
        UserPublicAppLink(
            keycloak_user_id=kid,
            application_id=application_id,
            created_at=utcnow(),
        )
    )
    db.commit()
    log_action(
        db,
        actor=actor,
        action="portal.public_link_add",
        target=app.slug,
        details={"application_id": application_id},
        ip_address=ip_address,
    )
    return True


def remove_public_link(
    db: Session,
    *,
    keycloak_user_id: str | None,
    application_id: int,
    actor: str,
    ip_address: str | None = None,
) -> bool:
    """Unpin a public_proxy link. Returns True if a row was deleted.

    Stale pins (app disabled / left managed set) can still be removed.
    """
    kid = (keycloak_user_id or "").strip()
    if not kid:
        raise PublicLinkError("Identité utilisateur requise pour Mes liens")
    app = db.query(App).filter_by(id=application_id).first()
    row = (
        db.query(UserPublicAppLink)
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
        action="portal.public_link_remove",
        target=(app.slug if app else str(application_id)),
        details={"application_id": application_id},
        ip_address=ip_address,
    )
    return True
