"""Native SSO login page (GET /login) and HTML POST /auth/login."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.breakglass_store import set_breakglass_password
from app.models import RealmConfig
from app.oidc_bff_client import InvalidCredentialsError, LoginStepResult, OidcTokenResult
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings, get_settings
from app.testing_framework.throttle import reset_throttles


OIDC_SECRET = "oidc-session-hmac-key-32bytes-min!!"
COOKIE = "bastion_session"


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    reset_throttles()
    yield
    reset_throttles()


def _add_realm(db: Session) -> None:
    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    db.add(
        RealmConfig(
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
    )
    db.commit()


@pytest.fixture()
def native_settings(monkeypatch):
    settings = Settings(
        environment="test",
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret-different",
        breakglass_jwt_secret_fallback_enabled=True,
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        oidc_native_session_enabled_realms="ar-systems",
        oidc_session_jwt_secret=OIDC_SECRET,
        oidc_session_cookie_name=COOKIE,
        oidc_session_max_age=3600,
        sso_portal_default_realm_slug="ar-systems",
    )
    get_settings.cache_clear()
    monkeypatch.setattr("app.oidc_bff.get_settings", lambda: settings)
    from app.main import app

    app.dependency_overrides[get_settings] = lambda: settings
    yield settings
    app.dependency_overrides.pop(get_settings, None)
    get_settings.cache_clear()


def test_get_login_shows_native_form_not_keycloak_redirect(
    client: TestClient, db_session: Session, native_settings: Settings
):
    _add_realm(db_session)
    set_breakglass_password(db_session, "admin", "super-secret-password")

    response = client.get("/login?rd=/catalogue", headers={"X-Real-IP": "10.0.0.50"})

    assert response.status_code == 200
    assert 'action="/auth/login"' in response.text
    assert 'id="oidc-username"' in response.text
    assert "Se connecter via SSO / Identifiant Unique" in response.text
    assert "Connexion locale (Administration / Secours)" in response.text
    assert 'action="/auth/breakglass"' in response.text
    assert 'data-initial-panel="sso"' in response.text


def test_get_login_hides_breakglass_on_public_ip(
    client: TestClient, db_session: Session, native_settings: Settings
):
    _add_realm(db_session)
    set_breakglass_password(db_session, "admin", "super-secret-password")

    response = client.get("/login", headers={"X-Real-IP": "203.0.113.10"})

    assert response.status_code == 200
    assert 'action="/auth/login"' in response.text
    assert "break-glass" not in response.text.lower()
    assert 'action="/auth/breakglass"' not in response.text


def test_html_post_login_success_redirects(
    client: TestClient, db_session: Session, native_settings: Settings
):
    _add_realm(db_session)
    tokens = OidcTokenResult(
        access_token="a",
        refresh_token="r",
        id_token="i",
        expires_in=300,
        sub="kc-sub-1",
        preferred_username="alice",
        claims={"sub": "kc-sub-1"},
    )
    with patch(
        "app.oidc_bff.start_headless_login",
        new=AsyncMock(return_value=LoginStepResult(status="success", tokens=tokens)),
    ):
        response = client.post(
            "/auth/login",
            data={
                "username": "alice",
                "password": "secret",
                "rd": "/catalogue",
            },
            headers={"X-Real-IP": "10.0.0.20"},
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert response.headers["location"] == "/catalogue"
    assert COOKIE in response.cookies


def test_html_post_login_invalid_shows_generic_error(
    client: TestClient, db_session: Session, native_settings: Settings
):
    _add_realm(db_session)
    with patch(
        "app.oidc_bff.start_headless_login",
        new=AsyncMock(side_effect=InvalidCredentialsError("bad")),
    ):
        response = client.post(
            "/auth/login",
            data={
                "username": "alice",
                "password": "wrong",
                "rd": "/apps",
            },
            headers={"X-Real-IP": "10.0.0.21"},
        )

    assert response.status_code == 200
    assert "Identifiants invalides" in response.text
    assert "utilisateur inconnu" not in response.text.lower()
    assert "mauvais mot de passe" not in response.text.lower()
    assert COOKIE not in response.cookies


def _add_client_realm(db: Session) -> None:
    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    db.add(
        RealmConfig(
            slug="clients",
            name="Clients externes",
            issuer_url="https://keycloak.example/realms/clients",
            client_id="portal-clients",
            client_secret_encrypted=encrypt_secret("secret", settings),
            redirect_uri="https://portal.example/oauth2/clients/callback",
            oauth2_proxy_port=4181,
            is_default=False,
            enabled=True,
            last_test_status="ok",
        )
    )
    db.commit()


@pytest.fixture()
def multi_native_settings(monkeypatch):
    settings = Settings(
        environment="test",
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret-different",
        breakglass_jwt_secret_fallback_enabled=True,
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        oidc_native_session_enabled_realms="ar-systems,clients",
        oidc_session_jwt_secret=OIDC_SECRET,
        oidc_session_cookie_name=COOKIE,
        oidc_session_max_age=3600,
        sso_portal_default_realm_slug="ar-systems",
    )
    get_settings.cache_clear()
    monkeypatch.setattr("app.oidc_bff.get_settings", lambda: settings)
    from app.main import app

    app.dependency_overrides[get_settings] = lambda: settings
    yield settings
    app.dependency_overrides.pop(get_settings, None)
    get_settings.cache_clear()


def test_login_audience_labels():
    from app.web.pages import _login_audience_label

    assert (
        _login_audience_label(
            RealmConfig(slug="ar-systems", name="AR-SYSTEMS")
        )
        == "Interne"
    )
    assert (
        _login_audience_label(RealmConfig(slug="clients", name="Clients externes"))
        == "Clients"
    )
    assert (
        _login_audience_label(RealmConfig(slug="partners", name="Partenaires"))
        == "Partenaires"
    )
    assert (
        _login_audience_label(
            RealmConfig(slug="foo", name="Foo", login_label="Société A")
        )
        == "Société A"
    )


def test_get_login_hides_realm_when_show_on_login_false(
    client: TestClient, db_session: Session, multi_native_settings: Settings
):
    _add_realm(db_session)
    _add_client_realm(db_session)
    clients = db_session.query(RealmConfig).filter_by(slug="clients").one()
    clients.show_on_login = False
    db_session.commit()

    response = client.get("/login", headers={"X-Real-IP": "203.0.113.10"})

    assert response.status_code == 200
    assert 'id="login-realm" value="ar-systems"' in response.text
    assert 'data-login-realm="clients"' not in response.text
    assert 'class="login-audience"' not in response.text


def test_get_login_shows_interne_clients_chooser(
    client: TestClient, db_session: Session, multi_native_settings: Settings
):
    _add_realm(db_session)
    _add_client_realm(db_session)

    response = client.get("/login", headers={"X-Real-IP": "203.0.113.10"})

    assert response.status_code == 200
    assert 'class="login-audience"' in response.text
    assert 'data-login-realm="ar-systems"' in response.text
    assert 'data-login-realm="clients"' in response.text
    assert ">Interne<" in response.text
    assert ">Clients<" in response.text
    assert 'name="realm" id="login-realm" value="ar-systems"' in response.text
    assert "Connexion — Interne" in response.text


def test_get_login_realm_query_selects_clients(
    client: TestClient, db_session: Session, multi_native_settings: Settings
):
    _add_realm(db_session)
    _add_client_realm(db_session)

    response = client.get(
        "/login?realm=clients", headers={"X-Real-IP": "203.0.113.10"}
    )

    assert response.status_code == 200
    assert 'id="login-realm" value="clients"' in response.text
    assert 'id="login-realm" value="ar-systems"' not in response.text
    assert 'data-login-realm="clients"' in response.text
    assert "Connexion — Clients" in response.text
    assert (
        'id="login-audience-clients"' in response.text
        and 'aria-selected="true"' in response.text
    )


def test_html_post_keeps_selected_realm_on_error(
    client: TestClient, db_session: Session, multi_native_settings: Settings
):
    _add_realm(db_session)
    _add_client_realm(db_session)
    with patch(
        "app.oidc_bff.start_headless_login",
        new=AsyncMock(side_effect=InvalidCredentialsError("bad")),
    ):
        response = client.post(
            "/auth/login",
            data={
                "username": "bob",
                "password": "wrong",
                "rd": "/apps",
                "realm": "clients",
            },
            headers={"X-Real-IP": "203.0.113.11"},
        )

    assert response.status_code == 200
    assert 'name="realm" id="login-realm" value="clients"' in response.text
    assert "Connexion — Clients" in response.text
    assert 'data-login-realm="clients"' in response.text


def test_get_login_chooser_includes_proxy_only_realm(
    client: TestClient, db_session: Session, native_settings: Settings
):
    """Chooser appears when a second realm exists even without native pilot."""
    _add_realm(db_session)
    _add_client_realm(db_session)

    response = client.get("/login", headers={"X-Real-IP": "203.0.113.10"})

    assert response.status_code == 200
    assert 'class="login-audience"' in response.text
    assert 'data-login-realm="ar-systems"' in response.text
    assert 'data-login-realm="clients"' in response.text
    assert ">Interne<" in response.text
    assert ">Clients<" in response.text
    assert 'id="oidc-username"' in response.text
    assert "Connexion — Interne" in response.text


def test_get_login_clients_tab_uses_oauth2_when_not_native(
    client: TestClient, db_session: Session, native_settings: Settings
):
    _add_realm(db_session)
    _add_client_realm(db_session)

    response = client.get(
        "/login?realm=clients", headers={"X-Real-IP": "203.0.113.10"}
    )

    assert response.status_code == 200
    assert 'class="login-audience"' in response.text
    assert "/oauth2/clients/start" in response.text
    assert 'id="oidc-username"' not in response.text
    assert "Connexion — Clients" in response.text


def test_get_login_single_realm_hides_chooser_and_interne_label(
    client: TestClient, db_session: Session, native_settings: Settings
):
    _add_realm(db_session)

    response = client.get("/login", headers={"X-Real-IP": "203.0.113.10"})

    assert response.status_code == 200
    assert 'class="login-audience"' not in response.text
    assert "Connexion — Interne" not in response.text
    assert "Connexion SSO — AR-SYSTEMS" in response.text
