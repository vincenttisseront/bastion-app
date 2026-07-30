"""Bastion account creation flow — internal row + Keycloak push (spec §1/§4)."""

import respx
from httpx import Response

from app.models import BastionAccount, RBACGroup, RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}
JSON_HEADERS = {**ADMIN_HEADERS, "Accept": "application/json"}

KC_BASE = "https://kc.example.com"
KC_ADMIN = f"{KC_BASE}/admin/realms/AR-SYSTEMS"
TOKEN_URL = f"{KC_BASE}/realms/AR-SYSTEMS/protocol/openid-connect/token"


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )


def _realm(db, *, provisioning_enabled: bool = True) -> RealmConfig:
    s = _settings()
    realm = RealmConfig(
        slug="ar-systems",
        name="AR-SYSTEMS",
        issuer_url=f"{KC_BASE}/realms/AR-SYSTEMS",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.test/oauth2/ar-systems/callback",
        oauth2_proxy_port=4180,
        enabled=True,
        groups_sync_enabled=True,
        keycloak_admin_client_id="bastion-admin-sync",
        keycloak_admin_client_secret_encrypted=encrypt_secret("sync-secret", s),
        keycloak_provision_client_id="bastion-admin-provision",
        keycloak_provision_client_secret_encrypted=encrypt_secret("prov-secret", s),
        provisioning_enabled=provisioning_enabled,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def _group(db, realm: RealmConfig) -> RBACGroup:
    group = RBACGroup(
        realm_id=realm.id,
        keycloak_group_id="g1",
        name="ARSYSTEMS-Users",
        path="/ARSYSTEMS-Users",
    )
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


def _mock_no_duplicate():
    respx.get(f"{KC_ADMIN}/users", params={"username": "jdoe", "exact": "true"}).respond(
        200, json=[]
    )
    respx.get(
        f"{KC_ADMIN}/users", params={"email": "jdoe@example.com", "exact": "true"}
    ).respond(200, json=[])


@respx.mock
def test_bastion_account_creation_success_with_group(client, db_session):
    realm = _realm(db_session)
    group = _group(db_session, realm)

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    _mock_no_duplicate()
    create_route = respx.post(f"{KC_ADMIN}/users").respond(
        201, headers={"Location": f"{KC_ADMIN}/users/kc-new-1"}
    )
    group_route = respx.put(f"{KC_ADMIN}/users/kc-new-1/groups/g1").respond(204)

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data={
            "realm_id": str(realm.id),
            "username": "jdoe",
            "email": "jdoe@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "group_ids": str(group.id),
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["status"] == "keycloak_created"
    assert body["keycloak_user_id"] == "kc-new-1"
    assert body["errors"] == []

    account = db_session.query(BastionAccount).filter_by(username="jdoe").first()
    assert account is not None
    assert account.status == "keycloak_created"
    assert account.keycloak_user_id == "kc-new-1"
    assert account.last_error is None
    assert group_route.called

    # Password policy: generated + UPDATE_PASSWORD temporary, never echoed.
    import json as _json

    sent = _json.loads(create_route.calls[0].request.content)
    assert sent["requiredActions"] == ["UPDATE_PASSWORD"]
    assert sent["credentials"][0]["temporary"] is True
    generated = sent["credentials"][0]["value"]
    assert len(generated) >= 20
    assert generated not in resp.text  # never displayed


@respx.mock
def test_bastion_account_duplicate_detected_before_write(client, db_session):
    """Exact pre-check finds an existing user → no POST /users write attempted."""
    realm = _realm(db_session)

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    respx.get(f"{KC_ADMIN}/users", params={"username": "jdoe", "exact": "true"}).respond(
        200, json=[{"id": "existing-1", "username": "jdoe"}]
    )
    create_route = respx.post(f"{KC_ADMIN}/users").respond(201)

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data={
            "realm_id": str(realm.id),
            "username": "jdoe",
            "email": "jdoe@example.com",
        },
    )
    assert resp.status_code == 502
    body = resp.json()
    assert body["ok"] is False
    assert "existe déjà" in body["errors"][0]

    assert not create_route.called  # write call avoided (spec §4/§7)
    account = db_session.query(BastionAccount).filter_by(username="jdoe").first()
    assert account.status == "pending"
    assert account.keycloak_user_id is None
    assert "existe déjà" in account.last_error


@respx.mock
def test_bastion_account_keycloak_failure_no_phantom(client, db_session):
    realm = _realm(db_session)

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    _mock_no_duplicate()
    respx.post(f"{KC_ADMIN}/users").respond(500)

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data={
            "realm_id": str(realm.id),
            "username": "jdoe",
            "email": "jdoe@example.com",
        },
    )
    assert resp.status_code == 502
    body = resp.json()
    assert body["ok"] is False
    assert body["status"] == "pending"

    account = db_session.query(BastionAccount).filter_by(username="jdoe").first()
    assert account.status == "pending"
    assert account.keycloak_user_id is None  # no phantom account
    assert "HTTP 500" in account.last_error


def test_bastion_account_creation_realm_not_enabled(client, db_session):
    realm = _realm(db_session, provisioning_enabled=False)

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data={
            "realm_id": str(realm.id),
            "username": "jdoe",
            "email": "jdoe@example.com",
        },
    )
    assert resp.status_code == 400
    assert "Provisioning non activé" in resp.json()["errors"]["_form"]
    assert db_session.query(BastionAccount).count() == 0


def test_bastion_account_creation_duplicate_internal(client, db_session):
    """Existing BastionAccount for (realm, username) blocks before any call."""
    realm = _realm(db_session)
    db_session.add(
        BastionAccount(
            realm_id=realm.id,
            username="jdoe",
            email="jdoe@example.com",
            status="keycloak_created",
            keycloak_user_id="kc-old",
            created_by="admin@example.com",
        )
    )
    db_session.commit()

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data={
            "realm_id": str(realm.id),
            "username": "jdoe",
            "email": "jdoe@example.com",
        },
    )
    assert resp.status_code == 400
    assert "existe déjà" in resp.json()["errors"]["_form"]
    assert db_session.query(BastionAccount).count() == 1


def test_users_new_form_renders_before_dynamic_route(client, db_session):
    """/admin/rbac/users/new must not be captured by /users/{keycloak_user_id}."""
    _realm(db_session)
    resp = client.get("/admin/rbac/users/new", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Nouvel utilisateur" in resp.text


@respx.mock
def test_bastion_account_creation_ignores_foreign_realm_group(client, db_session):
    """A group from another realm must never be assigned (UI + crafted POST)."""
    target = _realm(db_session)
    other = RealmConfig(
        slug="other",
        name="OTHER",
        issuer_url=f"{KC_BASE}/realms/OTHER",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", _settings()),
        redirect_uri="https://portal.test/oauth2/other/callback",
        oauth2_proxy_port=4181,
        enabled=True,
        keycloak_provision_client_id="bastion-admin-provision",
        keycloak_provision_client_secret_encrypted=encrypt_secret("prov-secret", _settings()),
        provisioning_enabled=True,
    )
    db_session.add(other)
    db_session.commit()
    db_session.refresh(other)
    foreign = _group(db_session, other)  # group belongs to OTHER, not target

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    _mock_no_duplicate()
    respx.post(f"{KC_ADMIN}/users").respond(
        201, headers={"Location": f"{KC_ADMIN}/users/kc-new-1"}
    )
    foreign_group_route = respx.put(
        f"{KC_ADMIN}/users/kc-new-1/groups/{foreign.keycloak_group_id}"
    ).respond(204)

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data={
            "realm_id": str(target.id),
            "username": "jdoe",
            "email": "jdoe@example.com",
            "group_ids": str(foreign.id),
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True
    assert not foreign_group_route.called


def test_users_new_form_groups_tagged_by_realm(client, db_session):
    """Each group checkbox carries data-realm-id for client-side filtering."""
    realm = _realm(db_session)
    group = _group(db_session, realm)
    resp = client.get("/admin/rbac/users/new", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert f'data-realm-id="{group.realm_id}"' in resp.text
    assert 'data-realm-select' in resp.text
    assert "groupes du realm cible" in resp.text.lower() or "Groupes du realm cible" in resp.text
