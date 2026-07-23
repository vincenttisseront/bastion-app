"""portal_admin self-revoke guard + dedicated audit actions."""

from __future__ import annotations

from app.models import AccessGrant, AuditLog
from app.rbac.grants_service import AccessGrantCreate, create_grant

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
    "X-User-Id": "kc-admin",
}

OTHER_ADMIN_HEADERS = {
    "X-Email": "other-admin@example.com",
    "X-Preferred-Username": "other-admin",
    "X-Groups": "portal-admins",
    "X-User-Id": "kc-other-admin",
}

SELF_KC = "kc-admin"
OTHER_KC = "kc-bob"


def _json_headers(base: dict) -> dict:
    return {**base, "Accept": "application/json", "Content-Type": "application/json"}


def _grant_portal_admin(db, *, keycloak_user_id: str, display: str = "user") -> AccessGrant:
    return create_grant(
        db,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id=keycloak_user_id,
            user_display_cache=display,
            resource_type="system_role",
            system_role="portal_admin",
            access_level="view",
        ),
        granted_by="seed",
    )


def test_portal_admin_self_revoke_blocked(client, db_session):
    grant = _grant_portal_admin(db_session, keycloak_user_id=SELF_KC, display="admin")
    db_session.commit()
    grant_id = grant.id

    resp = client.post(
        f"/admin/rbac/grants/{grant_id}/delete",
        headers=_json_headers(ADMIN_HEADERS),
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["ok"] is False
    assert "propre rôle admin" in body["detail"]

    still = db_session.query(AccessGrant).filter_by(id=grant_id).first()
    assert still is not None
    assert still.system_role == "portal_admin"


def test_portal_admin_revoke_other_ok_with_dedicated_audit(client, db_session):
    grant = _grant_portal_admin(db_session, keycloak_user_id=OTHER_KC, display="bob")
    db_session.commit()
    grant_id = grant.id

    resp = client.post(
        f"/admin/rbac/grants/{grant_id}/delete",
        headers=_json_headers(ADMIN_HEADERS),
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert db_session.query(AccessGrant).filter_by(id=grant_id).first() is None

    dedicated = (
        db_session.query(AuditLog)
        .filter_by(action="portal_admin_grant_revoked")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert dedicated is not None
    assert dedicated.actor == "admin@example.com"
    assert dedicated.details["keycloak_user_id"] == OTHER_KC
    assert dedicated.details["system_role"] == "portal_admin"

    generic = (
        db_session.query(AuditLog)
        .filter_by(action="rbac.grant.deleted")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert generic is not None


def test_portal_admin_grant_created_dedicated_audit(client, db_session):
    resp = client.post(
        "/admin/rbac/grants",
        headers=_json_headers(OTHER_ADMIN_HEADERS),
        json={
            "subject_type": "user",
            "keycloak_user_id": OTHER_KC,
            "user_display_cache": "bob",
            "resource_type": "system_role",
            "system_role": "portal_admin",
            "access_level": "view",
        },
    )
    assert resp.status_code == 200, resp.text
    grant_id = resp.json()["grant"]["id"]

    dedicated = (
        db_session.query(AuditLog)
        .filter_by(action="portal_admin_grant_created")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert dedicated is not None
    assert dedicated.actor == "other-admin@example.com"
    assert dedicated.details["keycloak_user_id"] == OTHER_KC
    assert dedicated.target == f"grant:{grant_id}"

    generic = (
        db_session.query(AuditLog)
        .filter_by(action="rbac.grant.created")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert generic is not None


def test_portal_admin_self_revoke_delete_method_blocked(client, db_session):
    grant = _grant_portal_admin(db_session, keycloak_user_id=SELF_KC, display="admin")
    db_session.commit()

    resp = client.delete(
        f"/admin/rbac/grants/{grant.id}",
        headers=_json_headers(ADMIN_HEADERS),
    )
    assert resp.status_code == 400
    assert db_session.query(AccessGrant).filter_by(id=grant.id).first() is not None
