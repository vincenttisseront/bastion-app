"""LOT 1 — permission modules / RbacRole seed + AccessGrant rbac_role."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.models import AccessGrant, PermissionModule, RbacRole, RolePermission
from app.rbac.grants_service import AccessGrantCreate, create_grant
from app.rbac.permission_seed import (
    DEFAULT_MODULES,
    SECURITY_ADMIN_ROLE_NAME,
    seed_governance_rbac,
)
from app.rbac.governance_service import apply_permission_diff, permissions_matrix_for_role


def test_rbac_permission_modules_seed(db_session: Session):
    report = seed_governance_rbac(db_session)
    db_session.commit()

    assert report["modules"] == len(DEFAULT_MODULES)
    assert report["roles"] == 1
    assert report["role_permissions"] == len(DEFAULT_MODULES)
    assert report["role_name"] == SECURITY_ADMIN_ROLE_NAME

    modules = db_session.query(PermissionModule).all()
    keys = {m.key for m in modules}
    assert "dashboard" in keys
    assert "secret_vault" in keys
    assert "rbac" in keys

    role = db_session.query(RbacRole).filter_by(name=SECURITY_ADMIN_ROLE_NAME).one()
    assert role.is_critical is True

    dash = db_session.query(PermissionModule).filter_by(key="dashboard").one()
    dash_perm = (
        db_session.query(RolePermission)
        .filter_by(role_id=role.id, module_id=dash.id)
        .one()
    )
    assert dash_perm.can_read is True
    assert dash_perm.locked is True

    vault = db_session.query(PermissionModule).filter_by(key="secret_vault").one()
    vault_perm = (
        db_session.query(RolePermission)
        .filter_by(role_id=role.id, module_id=vault.id)
        .one()
    )
    assert vault_perm.can_write is True

    # Idempotent
    again = seed_governance_rbac(db_session)
    db_session.commit()
    assert again["modules"] == len(DEFAULT_MODULES)
    assert db_session.query(RbacRole).count() == 1


def test_rbac_permission_modules_access_grant_rbac_role(db_session: Session):
    seed_governance_rbac(db_session)
    db_session.commit()
    role = db_session.query(RbacRole).one()

    from app.models import RBACGroup

    group = RBACGroup(name="sec-ops")
    db_session.add(group)
    db_session.commit()
    db_session.refresh(group)

    grant = create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="rbac_role",
            rbac_role_id=role.id,
            access_level="view",
        ),
        granted_by="test",
    )
    db_session.commit()
    assert grant.rbac_role_id == role.id
    assert db_session.query(AccessGrant).filter_by(resource_type="rbac_role").count() == 1


def test_rbac_governance_matrix_locked_cell_rejected(db_session: Session):
    seed_governance_rbac(db_session)
    db_session.commit()
    role = db_session.query(RbacRole).one()
    matrix = permissions_matrix_for_role(db_session, role.id)
    dash = next(r for r in matrix if r["module"]["key"] == "dashboard")
    assert dash["permission"]["locked"] is True

    with pytest.raises(ValueError, match="verrouill"):
        apply_permission_diff(
            db_session,
            role.id,
            [
                {
                    "module_key": "dashboard",
                    "field": "can_delete",
                    "value": True,
                }
            ],
            actor="attacker",
        )
