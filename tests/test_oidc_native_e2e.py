"""End-to-end integration: native OIDC login → bastion_session → /internal/oauth2-auth.

Mocks Keycloak (auth form + 302 code + token) via respx. Does not mock bastion
handlers — covers the real BFF client, session minting, and auth_request path.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import jwt
import pytest
import respx
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy.orm import Session

from app.models import OidcSession, RealmConfig
from app.oidc_bff import OIDC_LOGIN_MAX_FAILURES
from app.oidc_bff_config_service import set_oidc_bff_config
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings, get_settings
from app.testing_framework.throttle import reset_throttles

KC = "http://keycloak.internal:8080"
REALM = "ar-systems"
AUTH = f"{KC}/realms/{REALM}/protocol/openid-connect/auth"
TOKEN = f"{KC}/realms/{REALM}/protocol/openid-connect/token"
LOGIN_ACTION = (
    f"{KC}/realms/{REALM}/login-actions/authenticate"
    "?session_code=abc&execution=exec1&client_id=bastion-bff&tab_id=tab1"
)
REDIRECT_URI = "https://portal.example/.bastion/oidc/callback"
OIDC_SECRET = "oidc-e2e-session-hmac-key-32bytes!!"
COOKIE = "bastion_session"


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    reset_throttles()
    yield
    reset_throttles()


@pytest.fixture()
def e2e_settings(monkeypatch):
    settings = Settings(
        environment="test",
        portal_domain="portal.example",
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret-different",
        breakglass_jwt_secret_fallback_enabled=True,
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        oauth2_proxy_default_url="http://127.0.0.1:4180",
        rfc1918_bypass_enabled=False,
        oidc_native_session_enabled_realms="ar-systems",
        oidc_session_jwt_secret=OIDC_SECRET,
        oidc_session_cookie_name=COOKIE,
        oidc_session_max_age=3600,
        sso_portal_default_realm_slug=REALM,
    )
    get_settings.cache_clear()
    monkeypatch.setattr("app.oidc_bff.get_settings", lambda: settings)
    monkeypatch.setattr("app.auth.get_settings", lambda: settings)
    from app.main import app

    app.dependency_overrides[get_settings] = lambda: settings
    yield settings
    app.dependency_overrides.pop(get_settings, None)
    get_settings.cache_clear()


def _add_realm(db: Session, settings: Settings) -> None:
    seed = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    db.add(
        RealmConfig(
            slug=REALM,
            name="AR-SYSTEMS",
            issuer_url=f"{KC}/realms/{REALM}",
            client_id="portal",
            client_secret_encrypted=encrypt_secret("secret", seed),
            redirect_uri="https://portal.example/oauth2/ar-systems/callback",
            oauth2_proxy_port=4180,
            is_default=True,
            enabled=True,
            last_test_status="ok",
        )
    )
    db.flush()
    set_oidc_bff_config(
        db,
        REALM,
        settings,
        base_url=KC,
        client_id="bastion-bff",
        client_secret="bff-secret",
        redirect_uri=REDIRECT_URI,
    )
    db.commit()


def _login_html(*, error: bool = False) -> str:
    err = (
        '<span id="input-error" class="kc-feedback-text">'
        "Invalid username or password.</span>"
        if error
        else ""
    )
    return f"""
    <html><body>
      {err}
      <form id="kc-form-login" action="{LOGIN_ACTION}" method="post">
        <input type="hidden" name="credentialId" value="">
        <input type="text" name="username" value="">
        <input type="password" name="password" value="">
        <input type="submit" value="Sign In">
      </form>
    </body></html>
    """


def _id_token(*, sub: str = "kc-sub-e2e", preferred: str = "alice") -> str:
    return jwt.encode(
        {"sub": sub, "preferred_username": preferred, "iss": f"{KC}/realms/{REALM}"},
        key="unit-test-hmac-key-32bytes-min!!",
        algorithm="HS256",
    )


def _mock_keycloak_success(*, password: str = "s3cret") -> tuple:
    """Wire respx Keycloak: auth HTML → 302 code → token. Reject wrong password."""
    auth_route = respx.get(AUTH).mock(
        return_value=Response(
            200, text=_login_html(), headers={"content-type": "text/html"}
        )
    )

    def _login(request):
        body = dict(parse_qs(request.content.decode()))
        submitted = (body.get("password") or [""])[0]
        if submitted != password:
            return Response(
                200,
                text=_login_html(error=True),
                headers={"content-type": "text/html"},
            )
        state = "fallback-state"
        if auth_route.called:
            auth_req = auth_route.calls.last.request
            state = parse_qs(urlparse(str(auth_req.url)).query)["state"][0]
        return Response(
            302,
            headers={"Location": f"{REDIRECT_URI}?code=auth-code-e2e&state={state}"},
        )

    login_route = respx.post(
        url__startswith=f"{KC}/realms/{REALM}/login-actions/authenticate"
    ).mock(side_effect=_login)

    token_route = respx.post(TOKEN).mock(
        return_value=Response(
            200,
            json={
                "access_token": "access-e2e",
                "refresh_token": "refresh-e2e",
                "id_token": _id_token(),
                "expires_in": 300,
                "token_type": "Bearer",
            },
        )
    )
    return auth_route, login_route, token_route


@respx.mock
def test_e2e_login_sets_cookie_and_oauth2_auth_accepts(
    client: TestClient, db_session: Session, e2e_settings: Settings
):
    _add_realm(db_session, e2e_settings)
    auth_route, login_route, token_route = _mock_keycloak_success()
    # oauth2-proxy must NOT be required when native session is valid
    oauth2_route = respx.get("http://127.0.0.1:4180/oauth2/auth").mock(
        return_value=Response(401)
    )

    login = client.post(
        "/auth/login",
        data={"username": "alice", "password": "s3cret"},
        headers={"X-Real-IP": "10.0.0.40"},
    )
    assert login.status_code == 200
    assert login.json()["status"] == "ok"
    assert COOKIE in login.cookies
    assert auth_route.called and login_route.called and token_route.called

    rows = db_session.query(OidcSession).all()
    assert len(rows) == 1
    assert rows[0].sub == "kc-sub-e2e"
    assert rows[0].revoked is False

    client.cookies.set(COOKIE, login.cookies[COOKIE])
    auth = client.get("/internal/oauth2-auth")
    assert auth.status_code == 200
    assert auth.headers.get("x-auth-request-user") == "kc-sub-e2e"
    assert auth.headers.get("x-auth-request-preferred-username") == "alice"
    assert not oauth2_route.called


@respx.mock
def test_e2e_bad_password_401_no_session_row(
    client: TestClient, db_session: Session, e2e_settings: Settings
):
    _add_realm(db_session, e2e_settings)
    _mock_keycloak_success()

    response = client.post(
        "/auth/login",
        data={"username": "alice", "password": "wrong-password"},
        headers={"X-Real-IP": "10.0.0.41"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Identifiants invalides."
    assert COOKIE not in response.cookies
    assert db_session.query(OidcSession).count() == 0


@respx.mock
def test_e2e_logout_revokes_then_oauth2_auth_401(
    client: TestClient, db_session: Session, e2e_settings: Settings
):
    _add_realm(db_session, e2e_settings)
    _mock_keycloak_success()
    respx.get("http://127.0.0.1:4180/oauth2/auth").mock(return_value=Response(401))

    login = client.post(
        "/auth/login",
        data={"username": "alice", "password": "s3cret"},
        headers={"X-Real-IP": "10.0.0.42"},
    )
    assert login.status_code == 200
    cookie = login.cookies[COOKIE]
    client.cookies.set(COOKIE, cookie)

    assert client.get("/internal/oauth2-auth").status_code == 200

    logout = client.post("/auth/logout")
    assert logout.status_code == 200

    row = db_session.query(OidcSession).one()
    db_session.refresh(row)
    assert row.revoked is True

    # Keep presenting the old JWT after logout — must be rejected.
    client.cookies.set(COOKIE, cookie)
    denied = client.get("/internal/oauth2-auth")
    assert denied.status_code == 401


@respx.mock
def test_e2e_rate_limit_after_failures(
    client: TestClient, db_session: Session, e2e_settings: Settings
):
    _add_realm(db_session, e2e_settings)
    _mock_keycloak_success()

    for _ in range(OIDC_LOGIN_MAX_FAILURES):
        r = client.post(
            "/auth/login",
            data={"username": "bob", "password": "wrong"},
            headers={"X-Real-IP": "10.0.0.43"},
        )
        assert r.status_code == 401

    blocked = client.post(
        "/auth/login",
        data={"username": "bob", "password": "wrong"},
        headers={"X-Real-IP": "10.0.0.43"},
    )
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
    assert db_session.query(OidcSession).count() == 0
