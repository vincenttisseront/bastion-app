"""Access grant business logic and effective rights computation."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from pydantic import BaseModel, field_validator, model_validator
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import AccessGrant, App, FileResource, RBACGroup, RealmConfig
from app.rbac.keycloak_admin import fetch_group_members, fetch_user_groups

SUBJECT_TYPES = frozenset({"group", "user"})
RESOURCE_TYPES = frozenset({"application", "system_role", "rbac_role", "file", "folder"})
ACCESS_LEVELS = frozenset({"view", "launch", "manage"})

SYSTEM_ROLES: dict[str, str] = {
    "portal_admin": "Administrateur portail",
    "portal_auditor": "Auditeur (lecture audit)",
}


class AccessGrantCreate(BaseModel):
    subject_type: str
    rbac_group_id: int | None = None
    keycloak_user_id: str | None = None
    user_display_cache: str | None = None
    resource_type: str
    application_id: int | None = None
    system_role: str | None = None
    rbac_role_id: int | None = None
    file_id: int | None = None
    folder_id: int | None = None
    access_level: str = "view"

    @field_validator("subject_type")
    @classmethod
    def validate_subject_type(cls, value: str) -> str:
        if value not in SUBJECT_TYPES:
            raise ValueError("subject_type must be group or user")
        return value

    @field_validator("resource_type")
    @classmethod
    def validate_resource_type(cls, value: str) -> str:
        if value not in RESOURCE_TYPES:
            raise ValueError(
                "resource_type must be application, system_role, rbac_role, file, or folder"
            )
        return value

    @field_validator("access_level")
    @classmethod
    def validate_access_level(cls, value: str) -> str:
        if value not in ACCESS_LEVELS:
            raise ValueError("access_level must be view, launch, or manage")
        return value

    @field_validator("system_role")
    @classmethod
    def validate_system_role(cls, value: str | None) -> str | None:
        if value is not None and value not in SYSTEM_ROLES:
            raise ValueError(f"system_role must be one of: {', '.join(SYSTEM_ROLES)}")
        return value

    @model_validator(mode="after")
    def validate_exclusive_fields(self) -> AccessGrantCreate:
        if self.subject_type == "group":
            if not self.rbac_group_id or self.keycloak_user_id:
                raise ValueError("group grants require rbac_group_id only")
        else:
            if not self.keycloak_user_id or self.rbac_group_id:
                raise ValueError("user grants require keycloak_user_id only")
        if self.resource_type == "application":
            if (
                not self.application_id
                or self.system_role
                or self.rbac_role_id
                or self.file_id
                or self.folder_id
            ):
                raise ValueError("application grants require application_id only")
        elif self.resource_type == "system_role":
            if (
                not self.system_role
                or self.application_id
                or self.rbac_role_id
                or self.file_id
                or self.folder_id
            ):
                raise ValueError("system_role grants require system_role only")
        elif self.resource_type == "rbac_role":
            if (
                not self.rbac_role_id
                or self.application_id
                or self.system_role
                or self.file_id
                or self.folder_id
            ):
                raise ValueError("rbac_role grants require rbac_role_id only")
        elif self.resource_type == "file":
            if (
                not self.file_id
                or self.application_id
                or self.system_role
                or self.rbac_role_id
                or self.folder_id
            ):
                raise ValueError("file grants require file_id only")
        else:
            if (
                not self.folder_id
                or self.application_id
                or self.system_role
                or self.rbac_role_id
                or self.file_id
            ):
                raise ValueError("folder grants require folder_id only")
        return self


def serialize_grant(grant: AccessGrant, db: Session) -> dict[str, Any]:
    app_label = None
    app_slug = None
    if grant.application_id:
        app = db.query(App).filter_by(id=grant.application_id).first()
        if app:
            app_label = app.label
            app_slug = app.slug
    group_name = None
    if grant.rbac_group_id:
        group = db.query(RBACGroup).filter_by(id=grant.rbac_group_id).first()
        group_name = group.name if group else None
    rbac_role_name = None
    if getattr(grant, "rbac_role_id", None):
        from app.models import RbacRole

        role = db.query(RbacRole).filter_by(id=grant.rbac_role_id).first()
        rbac_role_name = role.name if role else None
    file_label = None
    file_slug = None
    if getattr(grant, "file_id", None):
        fr = db.query(FileResource).filter_by(id=grant.file_id).first()
        if fr:
            file_label = fr.label
            file_slug = fr.slug
    folder_name = None
    if getattr(grant, "folder_id", None):
        from app.models import FileFolder

        folder = db.query(FileFolder).filter_by(id=grant.folder_id).first()
        folder_name = folder.name if folder else None
    return {
        "id": grant.id,
        "subject_type": grant.subject_type,
        "rbac_group_id": grant.rbac_group_id,
        "group_name": group_name,
        "keycloak_user_id": grant.keycloak_user_id,
        "user_display_cache": grant.user_display_cache,
        "resource_type": grant.resource_type,
        "application_id": grant.application_id,
        "application_label": app_label,
        "application_slug": app_slug,
        "system_role": grant.system_role,
        "system_role_label": SYSTEM_ROLES.get(grant.system_role or "", grant.system_role),
        "rbac_role_id": getattr(grant, "rbac_role_id", None),
        "rbac_role_name": rbac_role_name,
        "file_id": getattr(grant, "file_id", None),
        "file_label": file_label,
        "file_slug": file_slug,
        "folder_id": getattr(grant, "folder_id", None),
        "folder_name": folder_name,
        "access_level": grant.access_level,
        "granted_at": grant.granted_at.isoformat() if grant.granted_at else None,
        "granted_by": grant.granted_by,
    }


def list_grants(
    db: Session,
    *,
    rbac_group_id: int | None = None,
    keycloak_user_id: str | None = None,
    application_id: int | None = None,
    file_id: int | None = None,
    folder_id: int | None = None,
) -> list[AccessGrant]:
    query = db.query(AccessGrant).order_by(AccessGrant.granted_at.desc())
    if rbac_group_id is not None:
        query = query.filter(
            AccessGrant.subject_type == "group",
            AccessGrant.rbac_group_id == rbac_group_id,
        )
    if keycloak_user_id is not None:
        query = query.filter(
            AccessGrant.subject_type == "user",
            AccessGrant.keycloak_user_id == keycloak_user_id,
        )
    if application_id is not None:
        query = query.filter(
            AccessGrant.resource_type == "application",
            AccessGrant.application_id == application_id,
        )
    if file_id is not None:
        query = query.filter(
            AccessGrant.resource_type == "file",
            AccessGrant.file_id == file_id,
        )
    if folder_id is not None:
        query = query.filter(
            AccessGrant.resource_type == "folder",
            AccessGrant.folder_id == folder_id,
        )
    return query.all()


def list_users_with_direct_grants(db: Session) -> list[dict[str, Any]]:
    """Distinct SSO users that already have at least one individual AccessGrant.

    Used as the default list on /admin/rbac/users (no full Keycloak directory sync).
    """
    rows = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.subject_type == "user",
            AccessGrant.keycloak_user_id.is_not(None),
        )
        .order_by(AccessGrant.granted_at.desc())
        .all()
    )
    by_user: dict[str, dict[str, Any]] = {}
    for grant in rows:
        uid = str(grant.keycloak_user_id)
        entry = by_user.get(uid)
        if entry is None:
            by_user[uid] = {
                "keycloak_user_id": uid,
                "display": grant.user_display_cache or uid,
                "grant_count": 1,
                "has_portal_admin": (
                    grant.resource_type == "system_role"
                    and grant.system_role == "portal_admin"
                ),
            }
        else:
            entry["grant_count"] += 1
            if grant.resource_type == "system_role" and grant.system_role == "portal_admin":
                entry["has_portal_admin"] = True
            if (not entry.get("display") or entry["display"] == uid) and grant.user_display_cache:
                entry["display"] = grant.user_display_cache
    return sorted(by_user.values(), key=lambda u: (u["display"] or "").lower())


def count_grants_by_application(db: Session) -> dict[int, int]:
    """Return {application_id: grant_count} for application-scoped AccessGrants."""
    rows = (
        db.query(AccessGrant.application_id, func.count(AccessGrant.id))
        .filter(
            AccessGrant.resource_type == "application",
            AccessGrant.application_id.is_not(None),
        )
        .group_by(AccessGrant.application_id)
        .all()
    )
    return {int(app_id): int(count) for app_id, count in rows if app_id is not None}


def serialize_application_grant_row(
    grant: AccessGrant,
    db: Session,
    *,
    member_count: int | None = None,
) -> dict[str, Any]:
    row = serialize_grant(grant, db)
    if grant.subject_type == "group":
        group = (
            db.query(RBACGroup).filter_by(id=grant.rbac_group_id).first()
            if grant.rbac_group_id
            else None
        )
        cached = group.member_count if group else None
        row["member_count"] = member_count if member_count is not None else cached
        row["subject_label"] = row.get("group_name") or f"groupe:{grant.rbac_group_id}"
        row["subject_href"] = (
            f"/admin/rbac/groups/{grant.rbac_group_id}" if grant.rbac_group_id else None
        )
    else:
        display = row.get("user_display_cache") or grant.keycloak_user_id
        row["member_count"] = None
        row["subject_label"] = display
        row["subject_href"] = (
            f"/admin/rbac/users?keycloak_user_id={grant.keycloak_user_id}"
            if grant.keycloak_user_id
            else None
        )
    return row


async def build_application_access_view(
    db: Session,
    application_id: int,
    settings,
) -> dict[str, Any]:
    """Grants for one app + deduplicated people coverage for admin UI."""
    grants = list_grants(db, application_id=application_id)
    rows: list[dict[str, Any]] = []
    unique_people: set[str] = set()
    people_sources: dict[str, list[str]] = defaultdict(list)

    for grant in grants:
        member_count: int | None = None
        if grant.subject_type == "user" and grant.keycloak_user_id:
            uid = str(grant.keycloak_user_id)
            unique_people.add(uid)
            people_sources[uid].append("direct")
        elif grant.subject_type == "group" and grant.rbac_group_id:
            group = db.query(RBACGroup).filter_by(id=grant.rbac_group_id).first()
            if group and group.keycloak_group_id and group.realm_id:
                realm = db.query(RealmConfig).filter_by(id=group.realm_id).first()
                if realm and realm.groups_sync_enabled:
                    try:
                        members = await fetch_group_members(
                            realm, group.keycloak_group_id, settings
                        )
                        member_count = len(members)
                        group.member_count = member_count
                        for member in members:
                            mid = str(member.get("id") or "").strip()
                            if mid:
                                unique_people.add(mid)
                                people_sources[mid].append(f"via groupe {group.name}")
                    except Exception:
                        member_count = group.member_count
                else:
                    member_count = group.member_count if group else None
            else:
                member_count = group.member_count if group else None
        rows.append(serialize_application_grant_row(grant, db, member_count=member_count))

    return {
        "grants": rows,
        "grant_count": len(rows),
        "unique_people_count": len(unique_people),
        "people_sources": {
            uid: sorted(set(sources)) for uid, sources in people_sources.items()
        },
    }


async def build_file_access_view(
    db: Session,
    file_id: int,
    settings,
) -> dict[str, Any]:
    """Grants for one file resource — same shape as application access view."""
    grants = list_grants(db, file_id=file_id)
    rows: list[dict[str, Any]] = []
    unique_people: set[str] = set()
    people_sources: dict[str, list[str]] = defaultdict(list)

    for grant in grants:
        member_count: int | None = None
        if grant.subject_type == "user" and grant.keycloak_user_id:
            uid = str(grant.keycloak_user_id)
            unique_people.add(uid)
            people_sources[uid].append("direct")
        elif grant.subject_type == "group" and grant.rbac_group_id:
            group = db.query(RBACGroup).filter_by(id=grant.rbac_group_id).first()
            if group and group.keycloak_group_id and group.realm_id:
                realm = db.query(RealmConfig).filter_by(id=group.realm_id).first()
                if realm and realm.groups_sync_enabled:
                    try:
                        members = await fetch_group_members(
                            realm, group.keycloak_group_id, settings
                        )
                        member_count = len(members)
                        group.member_count = member_count
                        for member in members:
                            mid = str(member.get("id") or "").strip()
                            if mid:
                                unique_people.add(mid)
                                people_sources[mid].append(f"via groupe {group.name}")
                    except Exception:
                        member_count = group.member_count
                else:
                    member_count = group.member_count if group else None
            else:
                member_count = group.member_count if group else None
        rows.append(serialize_application_grant_row(grant, db, member_count=member_count))

    return {
        "grants": rows,
        "grant_count": len(rows),
        "unique_people_count": len(unique_people),
        "people_sources": {
            uid: sorted(set(sources)) for uid, sources in people_sources.items()
        },
    }


def build_grants_matrix(db: Session) -> dict[str, Any]:
    """Applications × Groups matrix (group grants only, read-only)."""
    apps = db.query(App).order_by(App.label).all()
    groups = db.query(RBACGroup).order_by(RBACGroup.name).all()
    grants = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.resource_type == "application",
            AccessGrant.subject_type == "group",
            AccessGrant.application_id.is_not(None),
            AccessGrant.rbac_group_id.is_not(None),
        )
        .all()
    )
    cells: dict[tuple[int, int], str] = {}
    for grant in grants:
        if grant.application_id is None or grant.rbac_group_id is None:
            continue
        cells[(grant.rbac_group_id, grant.application_id)] = grant.access_level

    return {
        "apps": [{"id": a.id, "label": a.label, "slug": a.slug} for a in apps],
        "groups": [{"id": g.id, "name": g.name, "path": g.path} for g in groups],
        "cells": {
            f"{group_id}:{app_id}": level for (group_id, app_id), level in cells.items()
        },
    }


def create_grant(db: Session, data: AccessGrantCreate, granted_by: str) -> AccessGrant:
    grant = AccessGrant(
        subject_type=data.subject_type,
        rbac_group_id=data.rbac_group_id,
        keycloak_user_id=data.keycloak_user_id,
        user_display_cache=data.user_display_cache,
        resource_type=data.resource_type,
        application_id=data.application_id,
        system_role=data.system_role,
        rbac_role_id=data.rbac_role_id,
        file_id=data.file_id,
        folder_id=data.folder_id,
        access_level=data.access_level,
        granted_by=granted_by,
    )
    db.add(grant)
    db.flush()
    return grant


def is_portal_admin_system_grant(grant: AccessGrant) -> bool:
    """True for AccessGrant rows that confer system_role=portal_admin."""
    return (
        (grant.resource_type or "") == "system_role"
        and (grant.system_role or "") == "portal_admin"
    )


def is_self_portal_admin_grant(
    grant: AccessGrant,
    *,
    actor_keycloak_user_id: str | None,
) -> bool:
    """
    True when ``grant`` is the actor's own user-scoped portal_admin grant.

    Group-scoped portal_admin grants are not treated as self-owned (an admin may
    still manage group membership / revoke a group role that happens to include them).
    """
    if not is_portal_admin_system_grant(grant):
        return False
    if (grant.subject_type or "") != "user":
        return False
    actor = (actor_keycloak_user_id or "").strip()
    subject = (grant.keycloak_user_id or "").strip()
    return bool(actor) and actor == subject


def delete_grant(db: Session, grant_id: int) -> AccessGrant | None:
    grant = db.query(AccessGrant).filter_by(id=grant_id).first()
    if grant:
        db.delete(grant)
        db.flush()
    return grant


def _effective_entry(
    grant: AccessGrant,
    db: Session,
    *,
    source: str,
    grant_id: int | None = None,
) -> dict[str, Any]:
    base = serialize_grant(grant, db)
    base["source"] = source
    base["grant_id"] = grant_id if grant_id is not None else grant.id
    return base


async def compute_effective_grants(
    db: Session,
    realm: RealmConfig,
    keycloak_user_id: str,
    settings,
) -> list[dict[str, Any]]:
    """Union of group-derived and direct user grants with provenance."""
    direct = list_grants(db, keycloak_user_id=keycloak_user_id)
    effective: list[dict[str, Any]] = [
        _effective_entry(g, db, source="direct") for g in direct
    ]

    kc_groups = await fetch_user_groups(realm, keycloak_user_id, settings)
    kc_group_ids = {str(g.get("id")) for g in kc_groups if g.get("id")}

    if kc_group_ids:
        rbac_groups = (
            db.query(RBACGroup)
            .filter(
                RBACGroup.realm_id == realm.id,
                RBACGroup.keycloak_group_id.in_(kc_group_ids),
            )
            .all()
        )
        for rbac_group in rbac_groups:
            for grant in list_grants(db, rbac_group_id=rbac_group.id):
                effective.append(
                    _effective_entry(
                        grant,
                        db,
                        source=f"via groupe {rbac_group.name}",
                        grant_id=grant.id,
                    )
                )

    return effective


def serialize_member(user: dict) -> dict[str, Any]:
    return {
        "id": user.get("id"),
        "username": user.get("username"),
        "email": user.get("email"),
        "firstName": user.get("firstName"),
        "lastName": user.get("lastName"),
        "enabled": user.get("enabled", True),
    }


def serialize_user_search_result(user: dict) -> dict[str, Any]:
    display = user.get("username") or user.get("email") or user.get("id")
    return {
        "id": user.get("id"),
        "username": user.get("username"),
        "email": user.get("email"),
        "emailVerified": user.get("emailVerified"),
        "display": display,
    }
