"""LOT 4 — governance matrix toggles + locked cell server rejection."""

from __future__ import annotations

import pytest

from app.models import PermissionModule, RbacRole, RolePermission
from app.rbac.governance_service import apply_permission_diff
from app.rbac.permission_seed import SECURITY_ADMIN_ROLE_NAME, seed_governance_rbac


ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def test_rbac_governance_matrix_page(client, db_session):
    seed_governance_rbac(db_session)
    db_session.commit()
    resp = client.get("/admin/rbac/governance", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Matrice de Permissions" in resp.text
    assert SECURITY_ADMIN_ROLE_NAME in resp.text
    assert "perm-toggle" in resp.text


def test_rbac_governance_matrix_toggle_and_locked(client, db_session):
    seed_governance_rbac(db_session)
    db_session.commit()
    role = db_session.query(RbacRole).filter_by(name=SECURITY_ADMIN_ROLE_NAME).one()
    logs = db_session.query(PermissionModule).filter_by(key="logs").one()

    resp = client.post(
        f"/admin/rbac/roles/{role.id}/permissions",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        json={
            "changes": [
                {"module_id": logs.id, "field": "can_execute", "value": True},
            ]
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["applied"]

    dash = db_session.query(PermissionModule).filter_by(key="dashboard").one()
    dash_perm = (
        db_session.query(RolePermission)
        .filter_by(role_id=role.id, module_id=dash.id)
        .one()
    )
    assert dash_perm.locked is True

    bad = client.post(
        f"/admin/rbac/roles/{role.id}/permissions",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        json={
            "changes": [
                {"module_id": dash.id, "field": "can_delete", "value": True},
            ]
        },
    )
    assert bad.status_code == 400
    assert "verrouill" in bad.json()["detail"].lower()


def test_rbac_governance_matrix_apply_diff_rejects_locked(db_session):
    seed_governance_rbac(db_session)
    db_session.commit()
    role = db_session.query(RbacRole).one()
    dash = db_session.query(PermissionModule).filter_by(key="dashboard").one()
    with pytest.raises(ValueError, match="verrouill"):
        apply_permission_diff(
            db_session,
            role.id,
            [{"module_id": dash.id, "field": "can_execute", "value": True}],
            actor="tester",
        )
