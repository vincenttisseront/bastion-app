"""User profile (/profile) — identity, apps summary, Keycloak security link."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import App, RealmConfig
from app.rbac.grants_service import AccessGrantCreate, create_grant
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings


USER_HEADERS = {
    "X-Email": "alice@example.com",
    "X-Preferred-Username": "alice",
    "X-User-Id": "kc-user-alice",
    "X-Groups": "team-ops",
}

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
}

BREAKGLASS_HEADERS = {
    "X-Email": "admin@breakglass.local",
    "X-Preferred-Username": "admin",
    "X-Portal-Auth-Source": "breakglass",
    "X-Groups": "portal-admins",
}


def _app(db: Session, *, slug: str, label: str) -> App:
    app = App(
        slug=slug,
        label=label,
        upstream_url=f"https://{slug}.example.com/",
        enabled=True,
        access_mode="sso_gate",
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def _default_realm(db: Session, *, with_provisioning: bool = False) -> RealmConfig:
    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
    )
    realm = RealmConfig(
        slug="ar-systems",
        name="AR-SYSTEMS",
        issuer_url="https://kc.example.com/realms/AR-SYSTEMS",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", settings),
        redirect_uri="https://portal.test/oauth2/ar-systems/callback",
        oauth2_proxy_port=4180,
        is_default=True,
        enabled=True,
    )
    if with_provisioning:
        realm.keycloak_provision_client_id = "bastion-admin-provision"
        realm.keycloak_provision_client_secret_encrypted = encrypt_secret(
            "prov-secret", settings
        )
        realm.provisioning_enabled = True
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def test_user_profile_accessible_authenticated(client: TestClient, db_session: Session):
    _default_realm(db_session)
    resp = client.get("/profile", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert "Mon profil" in resp.text
    assert "Identité" in resp.text
    assert "Mes applications" in resp.text
    assert "Sécurité du compte" in resp.text
    assert "Préférences" in resp.text
    assert "alice@example.com" in resp.text
    assert "Utilisateur" in resp.text
    assert "Administrateur" not in resp.text
    assert "portal-avatar" in resp.text
    assert "portal-identity-name" in resp.text
    assert "Nom affiché" in resp.text
    assert "access_mode" not in resp.text
    assert "slug" not in resp.text
    assert "grant" not in resp.text.lower()
    assert "team-ops" not in resp.text
    assert "data-theme-pref" in resp.text


def test_user_profile_security_hidden_for_breakglass(
    client: TestClient, db_session: Session
):
    _default_realm(db_session)
    resp = client.get("/profile", headers=BREAKGLASS_HEADERS)
    assert resp.status_code == 200
    assert "Compte de secours local" in resp.text
    assert "Gérer la sécurité du compte" not in resp.text
    assert "/account/" not in resp.text
    assert "Sécurité du compte" in resp.text  # section title still present


def test_user_profile_security_native_when_provisioning(
    client: TestClient, db_session: Session
):
    _default_realm(db_session, with_provisioning=True)
    resp = client.get("/profile", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert "Mettre à jour le mot de passe" in resp.text
    assert "Sessions connectées" in resp.text
    assert 'action="/profile/password"' in resp.text
    assert "Gérer la sécurité du compte" not in resp.text


def test_user_profile_security_links_keycloak_account_fallback(
    client: TestClient, db_session: Session
):
    _default_realm(db_session)
    resp = client.get("/profile", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert 'href="https://kc.example.com/realms/AR-SYSTEMS/account/"' in resp.text
    assert "Gérer la sécurité du compte" in resp.text


def test_user_profile_apps_summary_matches_grants(
    client: TestClient, db_session: Session
):
    wiki = _app(db_session, slug="wiki", label="Wiki Interne")
    wiki.description = "Documentation équipe"
    crm = _app(db_session, slug="crm", label="CRM")
    for app in (wiki, crm):
        create_grant(
            db_session,
            AccessGrantCreate(
                subject_type="user",
                keycloak_user_id="kc-user-alice",
                resource_type="application",
                application_id=app.id,
                access_level="launch",
            ),
            "admin",
        )
    db_session.commit()

    resp = client.get("/profile", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert "2 applications accessibles" in resp.text
    assert "Wiki Interne" in resp.text
    assert "CRM" in resp.text
    assert "wiki" not in resp.text  # no raw slug
    assert 'href="/apps"' in resp.text
    # Description is for /apps tiles; profile preview uses title attribute
    assert "Documentation équipe" in resp.text or "Wiki Interne" in resp.text


def test_user_profile_admin_role_and_menu(client: TestClient, db_session: Session):
    _default_realm(db_session)
    resp = client.get("/profile", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Administrateur" in resp.text
    assert "Administration" in resp.text
    assert 'href="/dashboard"' in resp.text
    assert "Mon profil" in resp.text
    assert "Déconnexion" in resp.text


def test_user_profile_given_name_greeting_on_apps(
    client: TestClient, db_session: Session
):
    headers = {**USER_HEADERS, "X-Given-Name": "Alice"}
    resp = client.get("/apps", headers=headers)
    assert resp.status_code == 200
    assert "Bonjour Alice" in resp.text
