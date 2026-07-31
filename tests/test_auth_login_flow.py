"""Auth login state machine tests."""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.breakglass_store import set_breakglass_password
from app.models import RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings


def _add_default_idp(db: Session) -> RealmConfig:
    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    realm = RealmConfig(
        slug="ar-systems",
        name="AR-SYSTEMS",
        issuer_url="https://keycloak.example/realms/ar-systems",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", settings),
        redirect_uri="https://portal.example/oauth2/ar-systems/callback",
        oauth2_proxy_port=4180,
        is_default=True,
        enabled=True,
        last_test_status="ok",
    )
    db.add(realm)
    db.commit()
    return realm


def test_login_shows_sso_and_local_when_default_realm_configured(
    client: TestClient, db_session: Session
):
    _add_default_idp(db_session)
    set_breakglass_password(db_session, "admin", "super-secret-password")

    response = client.get(
        "/auth/login?rd=/catalogue",
        headers={"X-Real-IP": "10.0.0.50"},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Connexion SSO Keycloak" in response.text
    assert "/oauth2/ar-systems/start?rd=%2Fcatalogue" in response.text
    assert 'name="username"' in response.text
    assert 'name="password"' in response.text


def test_login_remaps_dashboard_rd_to_apps(client: TestClient, db_session: Session):
    _add_default_idp(db_session)
    set_breakglass_password(db_session, "admin", "super-secret-password")

    response = client.get("/auth/login?rd=/dashboard", follow_redirects=False)

    assert response.status_code == 200
    assert "/oauth2/ar-systems/start?rd=%2Fapps" in response.text
    assert "rd=%2Fdashboard" not in response.text


def test_login_post_uses_breakglass_not_idp_redirect(client: TestClient, db_session: Session):
    _add_default_idp(db_session)
    set_breakglass_password(db_session, "admin", "super-secret-password")

    response = client.post(
        "/auth/login",
        data={"username": "admin", "password": "super-secret-password", "rd": "/dashboard"},
        headers={"X-Real-IP": "10.0.0.50"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == "/dashboard"
    assert "bg_session" in response.cookies


def test_login_redirects_to_setup_without_idp_or_account(client: TestClient):
    response = client.get("/auth/login?rd=/admin", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["location"] == "/auth/setup?rd=%2Fadmin"


def test_login_shows_local_form_only_when_breakglass_exists(client: TestClient, db_session: Session):
    set_breakglass_password(db_session, "admin", "super-secret-password")

    response = client.get("/auth/login", headers={"X-Real-IP": "10.0.0.50"})

    assert response.status_code == 200
    assert 'name="username"' in response.text
    assert 'name="password"' in response.text
    assert "Connexion SSO Keycloak" not in response.text
    assert "/oauth2/" not in response.text
    assert "Break-glass" not in response.text


def test_setup_forbidden_when_account_already_exists(client: TestClient, db_session: Session):
    set_breakglass_password(db_session, "admin", "super-secret-password")

    get_response = client.get("/auth/setup")
    post_response = client.post(
        "/auth/setup",
        data={
            "username": "other",
            "password": "long-enough-pass",
            "password_confirm": "long-enough-pass",
        },
    )

    assert get_response.status_code == 403
    assert post_response.status_code == 403


def test_setup_forbidden_when_idp_configured(client: TestClient, db_session: Session):
    _add_default_idp(db_session)

    assert client.get("/auth/setup").status_code == 403
    assert client.post(
        "/auth/setup",
        data={
            "username": "admin",
            "password": "long-enough-pass",
            "password_confirm": "long-enough-pass",
        },
    ).status_code == 403


def test_setup_creates_account_and_redirects(client: TestClient, db_session: Session):
    response = client.post(
        "/auth/setup?rd=/dashboard",
        data={
            "username": "bootstrap",
            "password": "initial-password-12",
            "password_confirm": "initial-password-12",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == "/dashboard"
    assert "bg_session" in response.cookies

    locked = client.get("/auth/setup")
    assert locked.status_code == 403


def test_internal_oauth2_auth_returns_no_idp_header_without_realm(client: TestClient):
    response = client.get("/internal/oauth2-auth")

    assert response.status_code == 401
    assert response.headers.get("x-auth-error") == "no-idp-configured"
