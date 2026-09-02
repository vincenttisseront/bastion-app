"""HTML fallbacks for admin/portal client errors — never raw JSON in the browser."""

from app.models import RBACGroup, RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}
BROWSER_HEADERS = {
    **ADMIN_HEADERS,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}
JSON_HEADERS = {
    **ADMIN_HEADERS,
    "Accept": "application/json",
}


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
        slug="ar-systems",
        name="AR-SYSTEMS",
        issuer_url="https://kc.example.com/realms/AR-SYSTEMS",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.test/oauth2/ar-systems/callback",
        oauth2_proxy_port=4180,
        enabled=True,
        groups_sync_enabled=True,
        provisioning_enabled=True,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def test_admin_validation_error_redirects_html_client(client):
    resp = client.get(
        "/admin/rbac/users/search",
        headers=BROWSER_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/admin"


def test_admin_validation_error_stays_json_for_api_client(client):
    resp = client.get(
        "/admin/rbac/users/search",
        headers=JSON_HEADERS,
    )
    assert resp.status_code == 422
    assert "application/json" in resp.headers.get("content-type", "")
    body = resp.json()
    assert body["code"] == "validation_error"


def test_admin_http_400_redirects_html_client(client, db_session):
    realm = _realm(db_session)
    group = RBACGroup(
        realm_id=realm.id,
        name="No-KC-Group",
        path="/No-KC-Group",
        keycloak_group_id=None,
    )
    db_session.add(group)
    db_session.commit()
    db_session.refresh(group)

    resp = client.get(
        f"/admin/rbac/groups/{group.id}/members",
        headers=BROWSER_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/admin"


def test_admin_http_400_stays_json_for_api_client(client, db_session):
    realm = _realm(db_session)
    group = RBACGroup(
        realm_id=realm.id,
        name="No-KC-Group",
        path="/No-KC-Group",
        keycloak_group_id=None,
    )
    db_session.add(group)
    db_session.commit()
    db_session.refresh(group)

    resp = client.get(
        f"/admin/rbac/groups/{group.id}/members",
        headers=JSON_HEADERS,
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "bad_request"


def test_errors_400_page_renders(client):
    resp = client.get("/errors/400")
    assert resp.status_code == 400
    assert "Requête invalide" in resp.text
    assert "application/json" not in resp.headers.get("content-type", "")
