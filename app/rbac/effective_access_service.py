"""Effective application access for end users (portal) and admin cross-views.

Resolves AccessGrant union (direct user + group-via-OIDC-groups claim),
deduplicates by application_id keeping the highest access_level, and returns
only enabled apps. Group matching uses RBACGroup.name ↔ token "groups" claim
(no Keycloak Admin API call).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from sqlalchemy.orm import Session

from app.access_modes import is_user_catalogue_mode
from app.models import AccessGrant, App, RBACGroup

ACCESS_LEVEL_RANK: dict[str, int] = {"view": 1, "launch": 2, "manage": 3}


@dataclass
class EffectiveAppAccess:
    """One enabled application with the user's highest effective access level."""

    app: App
    access_level: str
    sources: list[str] = field(default_factory=list)
    grant_ids: list[int] = field(default_factory=list)

    @property
    def can_launch(self) -> bool:
        return ACCESS_LEVEL_RANK.get(self.access_level, 0) >= ACCESS_LEVEL_RANK["launch"]

    @property
    def application_id(self) -> int:
        return self.app.id


def _rank(level: str | None) -> int:
    return ACCESS_LEVEL_RANK.get(level or "", 0)


def _merge_candidate(
    by_app: dict[int, EffectiveAppAccess],
    *,
    app: App,
    access_level: str,
    source: str,
    grant_id: int,
) -> None:
    existing = by_app.get(app.id)
    if existing is None:
        by_app[app.id] = EffectiveAppAccess(
            app=app,
            access_level=access_level,
            sources=[source],
            grant_ids=[grant_id],
        )
        return
    if _rank(access_level) > _rank(existing.access_level):
        existing.access_level = access_level
    if source not in existing.sources:
        existing.sources.append(source)
    if grant_id not in existing.grant_ids:
        existing.grant_ids.append(grant_id)


def get_effective_apps_for_user(
    db: Session,
    *,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
) -> list[EffectiveAppAccess]:
    """Return enabled apps the user can access, deduped by highest access_level.

    Direct grants: subject_type=user, keycloak_user_id match.
    Group grants: subject_type=group where RBACGroup.name is in group_names
    (OIDC groups claim).
    """
    by_app: dict[int, EffectiveAppAccess] = {}
    names = [n for n in (group_names or []) if n]

    if keycloak_user_id:
        direct = (
            db.query(AccessGrant)
            .filter(
                AccessGrant.subject_type == "user",
                AccessGrant.keycloak_user_id == keycloak_user_id,
                AccessGrant.resource_type == "application",
                AccessGrant.application_id.is_not(None),
            )
            .all()
        )
        for grant in direct:
            app = db.query(App).filter_by(id=grant.application_id, enabled=True).first()
            if not app or not is_user_catalogue_mode(app.access_mode):
                continue
            _merge_candidate(
                by_app,
                app=app,
                access_level=grant.access_level or "view",
                source="direct",
                grant_id=grant.id,
            )

    if names:
        groups = db.query(RBACGroup).filter(RBACGroup.name.in_(names)).all()
        group_ids = [g.id for g in groups]
        group_by_id = {g.id: g for g in groups}
        if group_ids:
            group_grants = (
                db.query(AccessGrant)
                .filter(
                    AccessGrant.subject_type == "group",
                    AccessGrant.rbac_group_id.in_(group_ids),
                    AccessGrant.resource_type == "application",
                    AccessGrant.application_id.is_not(None),
                )
                .all()
            )
            for grant in group_grants:
                app = (
                    db.query(App)
                    .filter_by(id=grant.application_id, enabled=True)
                    .first()
                )
                if not app or not is_user_catalogue_mode(app.access_mode):
                    continue
                group = group_by_id.get(grant.rbac_group_id) if grant.rbac_group_id else None
                source = f"via groupe {group.name}" if group else "via groupe"
                _merge_candidate(
                    by_app,
                    app=app,
                    access_level=grant.access_level or "view",
                    source=source,
                    grant_id=grant.id,
                )

    return sorted(by_app.values(), key=lambda e: (e.app.label or "").lower())


def user_can_launch_application(
    db: Session,
    *,
    application_id: int,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
) -> bool:
    """True if effective AccessGrant grants at least ``launch`` on this application."""
    for entry in get_effective_apps_for_user(
        db,
        keycloak_user_id=keycloak_user_id,
        group_names=group_names,
    ):
        if entry.application_id == application_id and entry.can_launch:
            return True
    return False


def user_has_portal_admin_role(
    db: Session,
    *,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
) -> bool:
    """True if an AccessGrant grants system_role=portal_admin (direct or via group)."""
    if keycloak_user_id:
        direct = (
            db.query(AccessGrant)
            .filter(
                AccessGrant.subject_type == "user",
                AccessGrant.keycloak_user_id == keycloak_user_id,
                AccessGrant.resource_type == "system_role",
                AccessGrant.system_role == "portal_admin",
            )
            .first()
        )
        if direct:
            return True

    names = [n for n in (group_names or []) if n]
    if not names:
        return False
    groups = db.query(RBACGroup).filter(RBACGroup.name.in_(names)).all()
    group_ids = [g.id for g in groups]
    if not group_ids:
        return False
    return (
        db.query(AccessGrant)
        .filter(
            AccessGrant.subject_type == "group",
            AccessGrant.rbac_group_id.in_(group_ids),
            AccessGrant.resource_type == "system_role",
            AccessGrant.system_role == "portal_admin",
        )
        .first()
        is not None
    )
