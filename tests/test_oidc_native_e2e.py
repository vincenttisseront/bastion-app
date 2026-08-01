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


def _id_token(
    *,
    sub: str = "kc-sub-e2e",
    preferred: str = "alice",
    groups: list[str] | None = None,
    email: str | None = None,
) -> str:
    payload: dict = {
        "sub": sub,
        "preferred_username": preferred,
        "iss": f"{KC}/realms/{REALM}",
    }
    if groups is not None:
        payload["groups"] = groups
    if email is not None:
        payload["email"] = email
    return jwt.encode(
        payload,
        key="unit-test-hmac-key-32bytes-min!!",
        algorithm="HS256",
    )


def _mock_keycloak_success(
    *,
    password: str = "s3cret",
    groups: list[str] | None = None,
    email: str | None = None,
) -> tuple:
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

    id_groups = groups if groups is not None else ["/ARSYSTEMS-Users"]
    token_route = respx.post(TOKEN).mock(
        return_value=Response(
            200,
            json={
                "access_token": "access-e2e",
                "refresh_token": "refresh-e2e",
                "id_token": _id_token(groups=id_groups, email=email),
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
    assert auth.headers.get("x-auth-request-groups") == "ARSYSTEMS-Users"
    assert not oauth2_route.called


@respx.mock
def test_e2e_login_admin_api_groups_fallback_when_claim_missing(
    client: TestClient, db_session: Session, e2e_settings: Settings, monkeypatch
):
    """BFF client without groups mapper still populates X-Auth-Request-Groups via Admin API."""
    _add_realm(db_session, e2e_settings)
    _mock_keycloak_success(groups=[])

    async def _fake_fetch_user_groups(realm, keycloak_user_id, settings):
        assert keycloak_user_id == "kc-sub-e2e"
        return [{"id": "g1", "name": "ARSYSTEMS-Users", "path": "/ARSYSTEMS-Users"}]

    monkeypatch.setattr(
        "app.rbac.keycloak_admin.fetch_user_groups",
        _fake_fetch_user_groups,
    )

    login = client.post(
        "/auth/login",
        data={"username": "alice", "password": "s3cret"},
        headers={"X-Real-IP": "10.0.0.42"},
    )
    assert login.status_code == 200
    client.cookies.set(COOKIE, login.cookies[COOKIE])
    auth = client.get("/internal/oauth2-auth")
    assert auth.status_code == 200
    assert auth.headers.get("x-auth-request-groups") == "ARSYSTEMS-Users"


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


def _otp_html(*, error: bool = False) -> str:
    err = (
        '<span id="input-error" class="kc-feedback-text">Invalid authenticator code.</span>'
        if error
        else ""
    )
    return f"""
    <html><body>
      {err}
      <form id="kc-otp-login-form" action="{LOGIN_ACTION}&otp=1" method="post">
        <input type="hidden" name="session_code" value="otp-sess">
        <input type="hidden" name="execution" value="otp-exec">
        <input type="hidden" name="tab_id" value="tab-otp">
        <input type="text" name="otp" value="">
        <input type="submit" value="Submit">
      </form>
    </body></html>
    """


@respx.mock
def test_e2e_otp_flow_success(
    client: TestClient, db_session: Session, e2e_settings: Settings
):
    from app.models import AuditLog, OidcLoginAttempt

    _add_realm(db_session, e2e_settings)
    auth_route = respx.get(AUTH).mock(
        return_value=Response(200, text=_login_html(), headers={"content-type": "text/html"})
    )

    def _pw_login(request):
        return Response(
            200,
            text=_otp_html(),
            headers={"content-type": "text/html"},
        )

    login_route = respx.post(
        url__startswith=f"{KC}/realms/{REALM}/login-actions/authenticate"
    ).mock(side_effect=_pw_login)

    def _otp_submit(request):
        body = dict(parse_qs(request.content.decode()))
        code = (body.get("otp") or [""])[0]
        if code != "123456":
            return Response(
                200,
                text=_otp_html(error=True),
                headers={"content-type": "text/html"},
            )
        state = "fallback"
        if auth_route.called:
            state = parse_qs(urlparse(str(auth_route.calls[0].request.url)).query)[
                "state"
            ][0]
        return Response(
            302,
            headers={"Location": f"{REDIRECT_URI}?code=auth-code-otp&state={state}"},
        )

    # Second POST (OTP) hits same authenticate URL prefix — replace side_effect after first call.
    call_n = {"n": 0}

    def _authenticate(request):
        call_n["n"] += 1
        if call_n["n"] == 1:
            return _pw_login(request)
        return _otp_submit(request)

    login_route.side_effect = _authenticate

    respx.post(TOKEN).mock(
        return_value=Response(
            200,
            json={
                "access_token": "access-otp",
                "refresh_token": "refresh-otp",
                "id_token": _id_token(sub="kc-sub-otp", preferred="alice"),
                "expires_in": 300,
                "token_type": "Bearer",
            },
        )
    )

    step1 = client.post(
        "/auth/login",
        data={"username": "alice", "password": "s3cret"},
        headers={"X-Real-IP": "10.0.0.50"},
    )
    assert step1.status_code == 200
    body = step1.json()
    assert body["status"] == "otp_required"
    attempt_id = body["attempt_id"]
    assert db_session.query(OidcLoginAttempt).filter_by(attempt_id=attempt_id).count() == 1
    assert (
        db_session.query(AuditLog).filter_by(action="oidc_login_otp_required").count()
        >= 1
    )

    step2 = client.post(
        "/auth/login",
        data={"attempt_id": attempt_id, "otp_code": "123456"},
        headers={"X-Real-IP": "10.0.0.50"},
    )
    assert step2.status_code == 200
    assert step2.json()["status"] == "ok"
    assert COOKIE in step2.cookies
    assert db_session.query(OidcLoginAttempt).count() == 0
    assert db_session.query(OidcSession).filter_by(sub="kc-sub-otp").count() == 1
    assert (
        db_session.query(AuditLog).filter_by(action="oidc_login_otp_success").count()
        >= 1
    )

    # Single-use: reuse attempt_id → generic failure
    reuse = client.post(
        "/auth/login",
        data={"attempt_id": attempt_id, "otp_code": "123456"},
        headers={"X-Real-IP": "10.0.0.50"},
    )
    assert reuse.status_code == 401
    assert reuse.json()["detail"] == "Identifiants invalides."


@respx.mock
def test_e2e_otp_wrong_then_lockout(
    client: TestClient, db_session: Session, e2e_settings: Settings
):
    from app.models import OidcLoginAttempt
    from app.oidc_bff_client import MAX_OTP_FAILURES

    _add_realm(db_session, e2e_settings)
    respx.get(AUTH).mock(
        return_value=Response(200, text=_login_html(), headers={"content-type": "text/html"})
    )
    call_n = {"n": 0}

    def _authenticate(request):
        call_n["n"] += 1
        if call_n["n"] == 1:
            return Response(
                200, text=_otp_html(), headers={"content-type": "text/html"}
            )
        return Response(
            200, text=_otp_html(error=True), headers={"content-type": "text/html"}
        )

    respx.post(
        url__startswith=f"{KC}/realms/{REALM}/login-actions/authenticate"
    ).mock(side_effect=_authenticate)

    step1 = client.post(
        "/auth/login",
        data={"username": "alice", "password": "s3cret"},
        headers={"X-Real-IP": "10.0.0.51"},
    )
    attempt_id = step1.json()["attempt_id"]

    for i in range(MAX_OTP_FAILURES):
        bad = client.post(
            "/auth/login",
            data={"attempt_id": attempt_id, "otp_code": "000000"},
            headers={"X-Real-IP": "10.0.0.51"},
        )
        assert bad.status_code == 401
        assert bad.json()["detail"] == "Identifiants invalides."
        if i < MAX_OTP_FAILURES - 1:
            assert (
                db_session.query(OidcLoginAttempt)
                .filter_by(attempt_id=attempt_id)
                .count()
                == 1
            )

    assert db_session.query(OidcLoginAttempt).filter_by(attempt_id=attempt_id).count() == 0


@respx.mock
def test_e2e_otp_expired_attempt_generic_401(
    client: TestClient, db_session: Session, e2e_settings: Settings
):
    from datetime import timedelta

    from app.models import OidcLoginAttempt, utcnow
    from app.secret_crypto import encrypt_secret

    _add_realm(db_session, e2e_settings)
    past = utcnow() - timedelta(minutes=10)
    db_session.add(
        OidcLoginAttempt(
            attempt_id="expired-attempt-1",
            realm=REALM,
            username="alice",
            keycloak_cookies_encrypted=encrypt_secret("[]", e2e_settings),
            otp_form_encrypted=encrypt_secret(
                '{"action":"http://x","fields":{}}', e2e_settings
            ),
            code_verifier="v",
            state="s",
            keycloak_base_url=KC,
            keycloak_realm=REALM,
            client_id="bastion-bff",
            redirect_uri=REDIRECT_URI,
            otp_failures=0,
            created_at=past,
            expires_at=past,
        )
    )
    db_session.commit()

    resp = client.post(
        "/auth/login",
        data={"attempt_id": "expired-attempt-1", "otp_code": "123456"},
        headers={"X-Real-IP": "10.0.0.52"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Identifiants invalides."
    assert "expired" not in resp.text.lower()
