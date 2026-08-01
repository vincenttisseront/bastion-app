"""Native SSO login page (GET /login) and HTML POST /auth/login."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.breakglass_store import set_breakglass_password
from app.models import RealmConfig
from app.oidc_bff_client import InvalidCredentialsError, OidcTokenResult
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
    assert "Connexion SSO Keycloak" not in response.text
    assert "Accès break-glass administrateur" in response.text
    assert 'action="/auth/breakglass"' in response.text
    assert "ou accès d'urgence" in response.text


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
        "app.oidc_bff.perform_headless_login",
        new=AsyncMock(return_value=tokens),
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
        "app.oidc_bff.perform_headless_login",
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
