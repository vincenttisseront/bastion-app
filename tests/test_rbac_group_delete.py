"""Delete empty RBAC groups (Keycloak + Bastion)."""

import respx

from app.models import AccessGrant, BastionAccount, RBACGroup, RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}

KC_BASE = "https://kc.example.com"
REALM = "demo"
TOKEN_URL = f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/token"
GROUP_URL = f"{KC_BASE}/admin/realms/{REALM}/groups/kc-g-empty"


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )


def _realm(db) -> RealmConfig:
    s = _settings()
    realm = RealmConfig(
        slug="clients",
        name="clients",
        issuer_url=f"{KC_BASE}/realms/{REALM}",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.test/cb",
        oauth2_proxy_port=4180,
        enabled=True,
        groups_sync_enabled=True,
        keycloak_admin_client_id="bastion-admin-sync",
        keycloak_admin_client_secret_encrypted=encrypt_secret("admin-secret", s),
        keycloak_provision_client_id="bastion-admin-provision",
        keycloak_provision_client_secret_encrypted=encrypt_secret("prov-secret", s),
        provisioning_enabled=True,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def _group(db, realm: RealmConfig, *, members: int = 0, kc_id: str = "kc-g-empty") -> RBACGroup:
    group = RBACGroup(
        name="SDIS 81",
        path="/SDIS 81",
        realm_id=realm.id,
        keycloak_group_id=kc_id,
        member_count=members,
    )
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


def _token_mock():
    return respx.post(TOKEN_URL).respond(
        200,
        json={"access_token": "tok"},
        headers={"content-type": "application/json"},
    )


@respx.mock
def test_delete_empty_group_removes_keycloak_and_local(client, db_session):
    realm = _realm(db_session)
    group = _group(db_session, realm, members=0)
    db_session.add(
        AccessGrant(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="system_role",
            system_role="portal_admin",
            access_level="view",
            granted_by="admin@example.com",
        )
    )
    account = BastionAccount(
        realm_id=realm.id,
        username="pending",
        email="pending@example.com",
        status="pending_keycloak",
        origin="bastion",
        created_by="admin@example.com",
        pending_group_ids=[group.id, 999],
    )
    db_session.add(account)
    db_session.commit()
    gid = group.id

    _token_mock()
    respx.get(url__regex=r".*/groups/kc-g-empty/members.*").respond(200, json=[])
    respx.delete(GROUP_URL).respond(204)

    resp = client.post(
        f"/admin/rbac/groups/{gid}/delete",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
        data={"redirect_url": "/admin/rbac"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["grants_deleted"] == 1
    assert body["keycloak_deleted"] is True

    assert db_session.query(RBACGroup).filter_by(id=gid).first() is None
    assert db_session.query(AccessGrant).filter_by(rbac_group_id=gid).count() == 0
    db_session.refresh(account)
    assert account.pending_group_ids == [999]


@respx.mock
def test_delete_rejects_group_with_members(client, db_session):
    realm = _realm(db_session)
    group = _group(db_session, realm, members=2)
    gid = group.id

    _token_mock()
    respx.get(url__regex=r".*/groups/kc-g-empty/members.*").respond(
        200,
        json=[{"id": "u1", "username": "alice"}],
    )

    resp = client.post(
        f"/admin/rbac/groups/{gid}/delete",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
    )
    assert resp.status_code == 409
    assert "membre" in resp.json()["errors"]["_form"].lower()
    assert db_session.query(RBACGroup).filter_by(id=gid).first() is not None


@respx.mock
def test_delete_rejects_group_with_subgroups(client, db_session):
    realm = _realm(db_session)
    parent = _group(db_session, realm, members=0, kc_id="kc-parent")
    child = RBACGroup(
        name="child",
        path="/SDIS 81/child",
        realm_id=realm.id,
        keycloak_group_id="kc-child",
        member_count=0,
    )
    db_session.add(child)
    db_session.commit()

    _token_mock()
    respx.get(url__regex=r".*/groups/kc-parent/members.*").respond(200, json=[])

    resp = client.post(
        f"/admin/rbac/groups/{parent.id}/delete",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
    )
    assert resp.status_code == 409
    assert "sous-groupe" in resp.json()["errors"]["_form"].lower()
    assert db_session.query(RBACGroup).filter_by(id=parent.id).first() is not None


@respx.mock
def test_group_detail_shows_delete_when_empty(client, db_session):
    realm = _realm(db_session)
    group = _group(db_session, realm, members=0)

    _token_mock()
    respx.get(url__regex=r".*/groups/kc-g-empty/members.*").respond(200, json=[])

    resp = client.get(f"/admin/rbac/groups/{group.id}", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert f'action="/admin/rbac/groups/{group.id}/delete"' in resp.text
    assert "Supprimer" in resp.text
