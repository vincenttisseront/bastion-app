"""Seed data and helpers for internal Bastion Pro permission modules / roles."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import PermissionModule, RbacRole, RolePermission, utcnow

# Modules covering existing admin sections + Stitch mockup names.
DEFAULT_MODULES: list[dict] = [
    {
        "key": "dashboard",
        "label": "Dashboard",
        "description": "Tableau de bord administrateur",
        "icon": "dashboard",
        "sort_order": 10,
    },
    {
        "key": "sessions_audit",
        "label": "Sessions Audit",
        "description": "Sessions actives et journal d'audit",
        "icon": "history",
        "sort_order": 20,
    },
    {
        "key": "secret_vault",
        "label": "Secret Vault",
        "description": "Credentials applicatifs (vault)",
        "icon": "vpn_key",
        "sort_order": 30,
    },
    {
        "key": "network_map",
        "label": "Network Map",
        "description": "Cartographie réseau / infrastructure",
        "icon": "hub",
        "sort_order": 40,
    },
    {
        "key": "realms",
        "label": "Realms",
        "description": "Configuration OIDC / realms",
        "icon": "public",
        "sort_order": 50,
    },
    {
        "key": "rbac",
        "label": "RBAC",
        "description": "Groupes, utilisateurs et grants",
        "icon": "admin_panel_settings",
        "sort_order": 60,
    },
    {
        "key": "apps",
        "label": "Apps",
        "description": "Catalogue d'applications",
        "icon": "apps",
        "sort_order": 70,
    },
    {
        "key": "security",
        "label": "Sécurité",
        "description": "Paramètres de sécurité portail",
        "icon": "security",
        "sort_order": 90,
    },
    {
        "key": "logs",
        "label": "Logs",
        "description": "Journaux techniques",
        "icon": "terminal",
        "sort_order": 100,
    },
    {
        "key": "health",
        "label": "Santé",
        "description": "Santé des applications et dépendances",
        "icon": "monitor_heart",
        "sort_order": 110,
    },
]

SECURITY_ADMIN_ROLE_NAME = "Administrateur Sécurité"


def seed_permission_modules(db: Session) -> list[PermissionModule]:
    """Idempotent upsert of default PermissionModule rows."""
    out: list[PermissionModule] = []
    for spec in DEFAULT_MODULES:
        row = db.query(PermissionModule).filter_by(key=spec["key"]).first()
        if row is None:
            row = PermissionModule(**spec)
            db.add(row)
            db.flush()
        else:
            row.label = spec["label"]
            row.description = spec.get("description")
            row.icon = spec.get("icon")
            row.sort_order = spec.get("sort_order") or 0
        out.append(row)
    return out


def seed_security_admin_role(db: Session) -> RbacRole:
    """
    Ensure the default critical role exists with sensible permissions:
    - READ on all modules
    - WRITE on secret_vault
    - DELETE/EXECUTE locked on dashboard
    """
    modules = {m.key: m for m in seed_permission_modules(db)}
    role = db.query(RbacRole).filter_by(name=SECURITY_ADMIN_ROLE_NAME).first()
    if role is None:
        role = RbacRole(
            name=SECURITY_ADMIN_ROLE_NAME,
            is_critical=True,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(role)
        db.flush()

    for key, module in modules.items():
        perm = (
            db.query(RolePermission)
            .filter_by(role_id=role.id, module_id=module.id)
            .first()
        )
        if perm is None:
            perm = RolePermission(
                role_id=role.id,
                module_id=module.id,
                can_read=True,
                can_write=(key == "secret_vault"),
                can_delete=False,
                can_execute=False,
                locked=(key == "dashboard"),
                updated_by="seed",
            )
            db.add(perm)
        else:
            # Keep admin edits; only fill seed defaults when row was just created above.
            pass
    db.flush()
    return role


def seed_governance_rbac(db: Session) -> dict:
    """Run full seed; returns counts for migration/tests."""
    modules = seed_permission_modules(db)
    role = seed_security_admin_role(db)
    perms = db.query(RolePermission).filter_by(role_id=role.id).count()
    return {
        "modules": len(modules),
        "roles": 1,
        "role_permissions": perms,
        "role_name": role.name,
    }
