"""Access grant business logic and effective rights computation."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.orm import Session

from app.models import AccessGrant, App, RBACGroup, RealmConfig
from app.rbac.keycloak_admin import fetch_user_groups

SUBJECT_TYPES = frozenset({"group", "user"})
RESOURCE_TYPES = frozenset({"application", "system_role"})
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
            raise ValueError("resource_type must be application or system_role")
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
            if not self.application_id or self.system_role:
                raise ValueError("application grants require application_id only")
        else:
            if not self.system_role or self.application_id:
                raise ValueError("system_role grants require system_role only")
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
        "access_level": grant.access_level,
        "granted_at": grant.granted_at.isoformat() if grant.granted_at else None,
        "granted_by": grant.granted_by,
    }


def list_grants(
    db: Session,
    *,
    rbac_group_id: int | None = None,
    keycloak_user_id: str | None = None,
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
    return query.all()


def create_grant(db: Session, data: AccessGrantCreate, granted_by: str) -> AccessGrant:
    grant = AccessGrant(
        subject_type=data.subject_type,
        rbac_group_id=data.rbac_group_id,
        keycloak_user_id=data.keycloak_user_id,
        user_display_cache=data.user_display_cache,
        resource_type=data.resource_type,
        application_id=data.application_id,
        system_role=data.system_role,
        access_level=data.access_level,
        granted_by=granted_by,
    )
    db.add(grant)
    db.flush()
    return grant


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
        "display": display,
    }
