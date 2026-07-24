"""Internal Bastion Pro governance permissions (RbacRole × PermissionModule)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models import (
    AccessGrant,
    PermissionModule,
    RbacRole,
    RolePermission,
    utcnow,
)
from app.rbac.permission_seed import SECURITY_ADMIN_ROLE_NAME


def list_modules(db: Session) -> list[PermissionModule]:
    return db.query(PermissionModule).order_by(PermissionModule.sort_order).all()


def list_roles(db: Session) -> list[RbacRole]:
    return db.query(RbacRole).order_by(RbacRole.name).all()


def get_role(db: Session, role_id: int) -> RbacRole | None:
    return db.query(RbacRole).filter_by(id=role_id).first()


def get_role_by_name(db: Session, name: str) -> RbacRole | None:
    return db.query(RbacRole).filter_by(name=name).first()


def serialize_role(role: RbacRole) -> dict[str, Any]:
    parent = role.inherits_from.name if role.inherits_from else None
    return {
        "id": role.id,
        "name": role.name,
        "inherits_from_id": role.inherits_from_id,
        "inherits_from_name": parent,
        "is_critical": bool(role.is_critical),
        "created_at": role.created_at.isoformat() if role.created_at else None,
        "updated_at": role.updated_at.isoformat() if role.updated_at else None,
    }


def serialize_module(module: PermissionModule) -> dict[str, Any]:
    return {
        "id": module.id,
        "key": module.key,
        "label": module.label,
        "description": module.description,
        "icon": module.icon,
        "sort_order": module.sort_order,
    }


def serialize_permission(perm: RolePermission, module: PermissionModule | None = None) -> dict:
    mod = module or perm.module
    return {
        "id": perm.id,
        "role_id": perm.role_id,
        "module_id": perm.module_id,
        "module_key": mod.key if mod else None,
        "module_label": mod.label if mod else None,
        "can_read": bool(perm.can_read),
        "can_write": bool(perm.can_write),
        "can_delete": bool(perm.can_delete),
        "can_execute": bool(perm.can_execute),
        "locked": bool(perm.locked),
        "updated_at": perm.updated_at.isoformat() if perm.updated_at else None,
        "updated_by": perm.updated_by,
    }


def permissions_matrix_for_role(db: Session, role_id: int) -> list[dict[str, Any]]:
    """Return one row per module (create missing RolePermission as all-false)."""
    role = get_role(db, role_id)
    if role is None:
        return []
    modules = list_modules(db)
    existing = {
        p.module_id: p
        for p in db.query(RolePermission).filter_by(role_id=role_id).all()
    }
    rows: list[dict[str, Any]] = []
    for module in modules:
        perm = existing.get(module.id)
        if perm is None:
            perm = RolePermission(
                role_id=role_id,
                module_id=module.id,
                can_read=False,
                can_write=False,
                can_delete=False,
                can_execute=False,
                locked=(module.key == "dashboard"),
            )
            db.add(perm)
            db.flush()
            existing[module.id] = perm
        rows.append(
            {
                "module": serialize_module(module),
                "permission": serialize_permission(perm, module),
            }
        )
    return rows


def apply_permission_diff(
    db: Session,
    role_id: int,
    changes: list[dict[str, Any]],
    *,
    actor: str,
) -> list[dict[str, Any]]:
    """
    Apply cell changes. Rejects writes to locked cells (server-side).

    Each change: {module_id|module_key, field: can_read|..., value: bool}
    Returns list of applied audit details.
    """
    role = get_role(db, role_id)
    if role is None:
        raise ValueError("Rôle introuvable")

    applied: list[dict[str, Any]] = []
    for change in changes:
        module_id = change.get("module_id")
        module_key = change.get("module_key")
        field = change.get("field")
        value = bool(change.get("value"))
        if field not in ("can_read", "can_write", "can_delete", "can_execute"):
            raise ValueError(f"Champ de permission invalide: {field}")

        module: PermissionModule | None = None
        if module_id is not None:
            module = db.query(PermissionModule).filter_by(id=int(module_id)).first()
        elif module_key:
            module = db.query(PermissionModule).filter_by(key=str(module_key)).first()
        if module is None:
            raise ValueError("Module introuvable")

        perm = (
            db.query(RolePermission)
            .filter_by(role_id=role_id, module_id=module.id)
            .first()
        )
        if perm is None:
            perm = RolePermission(role_id=role_id, module_id=module.id)
            db.add(perm)
            db.flush()

        if perm.locked:
            raise ValueError(
                f"Permission verrouillée pour le module {module.key} (non modifiable)"
            )

        before = bool(getattr(perm, field))
        if before == value:
            continue
        setattr(perm, field, value)
        perm.updated_at = utcnow()
        perm.updated_by = actor
        role.updated_at = utcnow()
        applied.append(
            {
                "module": module.key,
                "action": field,
                "before": before,
                "after": value,
            }
        )
    db.flush()
    return applied


def create_role(
    db: Session,
    *,
    name: str,
    inherits_from_id: int | None = None,
    is_critical: bool = False,
) -> RbacRole:
    name = (name or "").strip()
    if not name:
        raise ValueError("Le nom du rôle est requis")
    if db.query(RbacRole).filter_by(name=name).first():
        raise ValueError("Un rôle avec ce nom existe déjà")
    if inherits_from_id is not None:
        parent = get_role(db, inherits_from_id)
        if parent is None:
            raise ValueError("Rôle parent introuvable")
        if parent.inherits_from_id is not None:
            # One-level inheritance only — refuse chaining.
            raise ValueError("L'héritage est limité à un niveau")

    role = RbacRole(
        name=name,
        inherits_from_id=inherits_from_id,
        is_critical=bool(is_critical),
    )
    db.add(role)
    db.flush()
    # Pre-create all-false permissions (dashboard locked).
    for module in list_modules(db):
        db.add(
            RolePermission(
                role_id=role.id,
                module_id=module.id,
                locked=(module.key == "dashboard"),
            )
        )
    db.flush()
    return role


def integrity_checks(db: Session) -> list[str]:
    """V1 integrity: duplicate names (impossible via unique) + inheritance depth."""
    issues: list[str] = []
    for role in list_roles(db):
        if role.inherits_from_id:
            parent = get_role(db, role.inherits_from_id)
            if parent is None:
                issues.append(f"Rôle « {role.name} » référence un parent manquant")
            elif parent.inherits_from_id is not None:
                issues.append(
                    f"Rôle « {role.name} » : héritage multi-niveaux non supporté"
                )
    return issues


def effective_flags_for_user(
    db: Session,
    *,
    keycloak_user_id: str | None,
    group_names: list[str] | None = None,
    module_key: str,
) -> dict[str, bool]:
    """
    Union of RolePermission flags from AccessGrant resource_type=rbac_role
    assigned to the user (direct or via group name).
    """
    from app.models import RBACGroup

    flags = {
        "can_read": False,
        "can_write": False,
        "can_delete": False,
        "can_execute": False,
    }
    module = db.query(PermissionModule).filter_by(key=module_key).first()
    if module is None:
        return flags

    role_ids: set[int] = set()
    if keycloak_user_id:
        for g in (
            db.query(AccessGrant)
            .filter_by(
                subject_type="user",
                keycloak_user_id=keycloak_user_id,
                resource_type="rbac_role",
            )
            .all()
        ):
            if g.rbac_role_id:
                role_ids.add(g.rbac_role_id)

    names = [n for n in (group_names or []) if n]
    if names:
        groups = db.query(RBACGroup).filter(RBACGroup.name.in_(names)).all()
        gids = [g.id for g in groups]
        if gids:
            for g in (
                db.query(AccessGrant)
                .filter(
                    AccessGrant.subject_type == "group",
                    AccessGrant.rbac_group_id.in_(gids),
                    AccessGrant.resource_type == "rbac_role",
                )
                .all()
            ):
                if g.rbac_role_id:
                    role_ids.add(g.rbac_role_id)

    if not role_ids:
        # Bootstrap: portal_admin system_role still implies full internal admin
        # until roles are assigned — callers may also check is_portal_admin.
        return flags

    for rid in role_ids:
        perm = (
            db.query(RolePermission)
            .filter_by(role_id=rid, module_id=module.id)
            .first()
        )
        if not perm:
            continue
        flags["can_read"] = flags["can_read"] or bool(perm.can_read)
        flags["can_write"] = flags["can_write"] or bool(perm.can_write)
        flags["can_delete"] = flags["can_delete"] or bool(perm.can_delete)
        flags["can_execute"] = flags["can_execute"] or bool(perm.can_execute)
    return flags


def user_can_module_action(
    db: Session,
    *,
    keycloak_user_id: str | None,
    group_names: list[str] | None,
    module_key: str,
    action: str,
    is_portal_admin: bool = False,
) -> bool:
    """
    Enforce a governance action. Portal admins (legacy system_role / groups) keep
    full access until explicit RbacRole grants are the sole path.
    """
    if is_portal_admin:
        return True
    if action not in ("can_read", "can_write", "can_delete", "can_execute"):
        return False
    flags = effective_flags_for_user(
        db,
        keycloak_user_id=keycloak_user_id,
        group_names=group_names,
        module_key=module_key,
    )
    return bool(flags.get(action))


DEFAULT_ROLE_NAME = SECURITY_ADMIN_ROLE_NAME


def role_distribution_summary(db: Session) -> dict[str, Any]:
    """
    Categorize RbacRole by permission breadth for the donut panel.
    read_only / ops / elevated — V1 heuristic on RolePermission flags.
    """
    read_only = ops = elevated = 0
    for role in list_roles(db):
        perms = db.query(RolePermission).filter_by(role_id=role.id).all()
        has_write = any(p.can_write or p.can_delete or p.can_execute for p in perms)
        has_elevated = any(p.can_delete or p.can_execute for p in perms)
        if has_elevated:
            elevated += 1
        elif has_write:
            ops += 1
        else:
            read_only += 1
    total = read_only + ops + elevated
    p1 = int(round(100.0 * read_only / total)) if total else 0
    p2 = p1 + (int(round(100.0 * ops / total)) if total else 0)
    return {
        "read_only": read_only,
        "ops": ops,
        "elevated": elevated,
        "total": total,
        "p1": p1,
        "p2": min(100, p2),
    }


def excess_permission_alerts(db: Session, *, days: int = 90) -> list[str]:
    """
    V1: RolePermission with write/delete true and updated_at older than ``days``,
    or never updated (created with seed and untouched).
    """
    from datetime import timedelta, timezone

    def _aware(value):
        if value is None:
            return None
        if getattr(value, "tzinfo", None) is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    cutoff = utcnow() - timedelta(days=days)
    alerts: list[str] = []
    for perm in db.query(RolePermission).all():
        if not (perm.can_write or perm.can_delete):
            continue
        updated = _aware(perm.updated_at)
        if updated is None or updated < cutoff:
            mod = perm.module.key if perm.module else str(perm.module_id)
            role = perm.role.name if perm.role else str(perm.role_id)
            age = "jamais mise à jour" if updated is None else f"depuis {updated.date()}"
            alerts.append(f"{role} / {mod}: write/delete {age}")
    return alerts[:12]
