import pytest
import respx
from httpx import Response

from app.admin.throttling import reset_test_rate_limits
from app.models import RBACGroup, RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _test_settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )


@pytest.fixture(autouse=True)
def _reset_limits():
    # shares dict with sync limiter
    reset_test_rate_limits()


def _make_realm(db, settings: Settings, **kwargs) -> RealmConfig:
    realm = RealmConfig(
        slug=kwargs.get("slug", "kc"),
        name=kwargs.get("name", "Keycloak"),
        issuer_url=kwargs.get("issuer_url", "https://kc.example.com/realms/demo"),
        client_id="login-client",
        client_secret_encrypted=encrypt_secret("login-secret", settings),
        redirect_uri=f"https://{settings.portal_domain}/oauth2/kc/callback",
        scopes="openid profile email",
        oauth2_proxy_port=4181,
        is_default=False,
        enabled=False,
        keycloak_admin_client_id=kwargs.get("admin_client_id", "bastion-admin-sync"),
        keycloak_admin_client_secret_encrypted=encrypt_secret("admin-secret", settings),
        groups_sync_enabled=True,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


@respx.mock
def test_sync_imports_and_updates_and_orphans(client, db_session):
    settings = _test_settings()
    realm = _make_realm(db_session, settings)

    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    groups_url = "https://kc.example.com/admin/realms/demo/groups?briefRepresentation=false"

    respx.post(token_url).respond(
        200, json={"access_token": "t"}, headers={"content-type": "application/json"}
    )
    respx.get(groups_url).respond(
        200,
        json=[
            {
                "id": "g1",
                "name": "portal-admins",
                "path": "/portal-admins",
                "subGroups": [{"id": "g2", "name": "sub", "path": "/portal-admins/sub"}],
            }
        ],
    )

    resp = client.post(
        f"/admin/rbac/groups/sync/{realm.id}",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["imported"] == 2
    assert data["updated"] == 0
    assert data["orphaned"] == 0

    # Second run with renamed group and missing subgroup => subgroup becomes orphan (not deleted)
    reset_test_rate_limits()
    respx.reset()
    respx.post(token_url).respond(
        200, json={"access_token": "t"}, headers={"content-type": "application/json"}
    )
    respx.get(groups_url).respond(
        200,
        json=[
            {"id": "g1", "name": "portal-admins-renamed", "path": "/portal-admins"}
        ],
    )
    resp2 = client.post(
        f"/admin/rbac/groups/sync/{realm.id}",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["updated"] == 1
    assert data2["orphaned"] == 1

    assert db_session.query(RBACGroup).filter_by(keycloak_group_id="g2").count() == 1


@respx.mock
def test_sync_errors_when_not_configured(client, db_session):
    settings = _test_settings()
    realm = _make_realm(db_session, settings, admin_client_id=None)
    realm.keycloak_admin_client_id = None
    realm.keycloak_admin_client_secret_encrypted = None
    realm.groups_sync_enabled = False
    db_session.commit()

    resp = client.post(
        f"/admin/rbac/groups/sync/{realm.id}",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
    )
    assert resp.status_code == 400
    assert "non activé" in resp.json()["errors"]["_form"].lower()


@respx.mock
def test_sync_invalid_client_message(client, db_session):
    settings = _test_settings()
    realm = _make_realm(db_session, settings)
    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    respx.post(token_url).respond(
        401,
        json={"error": "invalid_client"},
        headers={"content-type": "application/json"},
    )

    resp = client.post(
        f"/admin/rbac/groups/sync/{realm.id}",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
    )
    assert resp.status_code == 400
    assert "invalide" in resp.json()["errors"]["_form"].lower()


@respx.mock
def test_sync_403_role_missing_message(client, db_session):
    settings = _test_settings()
    realm = _make_realm(db_session, settings)
    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    groups_url = "https://kc.example.com/admin/realms/demo/groups?briefRepresentation=false"

    respx.post(token_url).respond(
        200, json={"access_token": "t"}, headers={"content-type": "application/json"}
    )
    respx.get(groups_url).respond(403, json={"error": "forbidden"})

    resp = client.post(
        f"/admin/rbac/groups/sync/{realm.id}",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
    )
    assert resp.status_code == 400
    assert "query-groups" in resp.json()["errors"]["_form"]

