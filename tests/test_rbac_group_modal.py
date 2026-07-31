"""LOT 3 — group role-config modal save + audit."""

from __future__ import annotations

from app.models import AccessGrant, AuditLog, RBACGroup, RbacRole
from app.rbac.permission_seed import SECURITY_ADMIN_ROLE_NAME, seed_governance_rbac


ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def test_rbac_group_modal_role_config_save(client, db_session):
    seed_governance_rbac(db_session)
    db_session.commit()
    group = RBACGroup(name="ops-team", description=None, group_tag=None)
    db_session.add(group)
    db_session.commit()
    db_session.refresh(group)

    resp = client.post(
        f"/admin/rbac/groups/{group.id}/role-config",
        headers={**ADMIN_HEADERS, "Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
        json={
            "mode": "total",
            "group_tag": "Critical Access",
            "description": "Équipe opérations",
        },
    )
    assert resp.status_code == 200
    assert resp.json().get("ok") is True

    db_session.expire_all()
    group2 = db_session.query(RBACGroup).filter_by(id=group.id).one()
    assert group2.group_tag == "Critical Access"
    assert group2.description == "Équipe opérations"

    role = db_session.query(RbacRole).filter_by(name=SECURITY_ADMIN_ROLE_NAME).one()
    grant = (
        db_session.query(AccessGrant)
        .filter_by(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="rbac_role",
        )
        .one()
    )
    assert grant.rbac_role_id == role.id
    assert grant.access_level == "manage"

    audit = (
        db_session.query(AuditLog)
        .filter_by(action="group_rbac_config_updated", target=f"rbac_group:{group.id}")
        .one()
    )
    assert audit.actor == "admin@example.com"


def test_rbac_groups_page_table_and_pagination(client, db_session):
    for i in range(12):
        db_session.add(RBACGroup(name=f"grp-{i:02d}", member_count=i))
    db_session.commit()

    resp = client.get("/admin/rbac?per_page=10", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Gestion des Groupes" in resp.text
    assert 'id="rbac-groups-table"' in resp.text
    assert "group-card" not in resp.text
    assert "grp-00" in resp.text
    assert "grp-09" in resp.text
    assert "grp-10" not in resp.text
    assert "Page 1 / 2" in resp.text

    page2 = client.get("/admin/rbac?per_page=10&page=2", headers=ADMIN_HEADERS)
    assert page2.status_code == 200
    assert "grp-10" in page2.text
    assert "grp-00" not in page2.text

    filtered = client.get("/admin/rbac?q=grp-05", headers=ADMIN_HEADERS)
    assert filtered.status_code == 200
    assert "grp-05" in filtered.text
    assert "grp-00" not in filtered.text
