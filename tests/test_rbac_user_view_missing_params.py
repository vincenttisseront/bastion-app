"""RBAC user fiche — missing query params must redirect, never raw JSON."""

from app.models import RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}

KC_BASE = "https://kc.example.com"


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
        issuer_url=f"{KC_BASE}/realms/AR-SYSTEMS",
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


def test_user_view_without_params_redirects_to_users_list(client):
    resp = client.get(
        "/admin/rbac/users/view",
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("/admin/rbac/users")
    assert "list_tab=open" in location


def test_user_view_without_params_returns_html_after_redirect(client):
    resp = client.get("/admin/rbac/users/view", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "json" not in (resp.headers.get("content-type") or "").lower()
    assert "Utilisateurs" in resp.text


def test_user_view_realm_only_redirects_with_realm_context(client, db_session):
    realm = _realm(db_session)
    resp = client.get(
        f"/admin/rbac/users/view?realm_id={realm.id}",
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert f"realm_id={realm.id}" in location
    assert "list_tab=open" in location
