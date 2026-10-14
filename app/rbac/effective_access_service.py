"""Effective application access for end users (portal) and admin cross-views.

Resolves AccessGrant union (direct user + group-via-OIDC-groups claim),
deduplicates by application_id keeping the highest access_level, and returns
only enabled apps. Group matching uses RBACGroup.name ↔ token "groups" claim
within the session realm (no Keycloak Admin API call).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from sqlalchemy import ColumnElement, and_, or_
from sqlalchemy.orm import Session

from app.access_modes import is_user_catalogue_mode
from app.models import AccessGrant, App, RBACGroup
from app.rbac.group_lookup import resolve_rbac_groups

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


def _subject_filter(
    db: Session,
    *,
    keycloak_user_id: str | None,
    realm_slug: str | None,
    group_names: Sequence[str] | None,
) -> tuple[ColumnElement[bool] | None, dict[int, RBACGroup]]:
    """SQL predicate matching the user's direct and group grants."""
    groups = resolve_rbac_groups(db, realm_slug=realm_slug, group_names=group_names)
    group_by_id = {g.id: g for g in groups}
    clauses: list[ColumnElement[bool]] = []
    if keycloak_user_id:
        clauses.append(
            and_(
                AccessGrant.subject_type == "user",
                AccessGrant.keycloak_user_id == keycloak_user_id,
            )
        )
    if group_by_id:
        clauses.append(
            and_(
                AccessGrant.subject_type == "group",
                AccessGrant.rbac_group_id.in_(list(group_by_id)),
            )
        )
    return (or_(*clauses) if clauses else None), group_by_id


def get_effective_apps_for_user(
    db: Session,
    *,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
    realm_slug: str | None = None,
    application_id: int | None = None,
) -> list[EffectiveAppAccess]:
    """Return enabled apps the user can access, deduped by highest access_level.

    Direct grants: subject_type=user, keycloak_user_id match.
    Group grants: subject_type=group on groups of ``realm_slug`` named in
    ``group_names`` (OIDC groups claim). ``application_id`` narrows the lookup
    to one application.
    """
    subject, group_by_id = _subject_filter(
        db,
        keycloak_user_id=keycloak_user_id,
        realm_slug=realm_slug,
        group_names=group_names,
    )
    if subject is None:
        return []
    query = (
        db.query(AccessGrant, App)
        .join(App, App.id == AccessGrant.application_id)
        .filter(
            subject,
            AccessGrant.resource_type == "application",
            App.enabled.is_(True),
        )
    )
    if application_id is not None:
        query = query.filter(App.id == application_id)

    by_app: dict[int, EffectiveAppAccess] = {}
    for grant, app in query.all():
        if not is_user_catalogue_mode(app.access_mode):
            continue
        if grant.subject_type == "user":
            source = "direct"
        else:
            group = group_by_id.get(grant.rbac_group_id)
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
    realm_slug: str | None = None,
) -> bool:
    """True if effective AccessGrant grants at least ``launch`` on this application."""
    entries = get_effective_apps_for_user(
        db,
        keycloak_user_id=keycloak_user_id,
        group_names=group_names,
        realm_slug=realm_slug,
        application_id=application_id,
    )
    return any(entry.can_launch for entry in entries)


def user_has_portal_admin_role(
    db: Session,
    *,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
    realm_slug: str | None = None,
) -> bool:
    """True if an AccessGrant grants system_role=portal_admin (direct or via group)."""
    subject, _ = _subject_filter(
        db,
        keycloak_user_id=keycloak_user_id,
        realm_slug=realm_slug,
        group_names=group_names,
    )
    if subject is None:
        return False
    return (
        db.query(AccessGrant.id)
        .filter(
            subject,
            AccessGrant.resource_type == "system_role",
            AccessGrant.system_role == "portal_admin",
        )
        .first()
        is not None
    )
