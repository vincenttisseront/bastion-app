"""Native OIDC BFF login / logout / session cookie validation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import AuditLog, OidcSession
from app.oidc_bff import (
    OIDC_LOGIN_MAX_FAILURES,
    issue_oidc_session,
    validate_oidc_session_cookie,
)
from app.oidc_bff_client import (
    InvalidCredentialsError,
    LoginStepResult,
    OidcTokenResult,
    UnsupportedAuthFlowError,
)
from app.sso_settings import Settings, get_settings
from app.testing_framework.throttle import reset_throttles


OIDC_SECRET = "oidc-session-hmac-key-32bytes-min!!"
COOKIE = "bastion_session"


@pytest.fixture(autouse=True)
def _reset_oidc_rate_limits():
    reset_throttles()
    yield
    reset_throttles()


@pytest.fixture()
def oidc_settings(monkeypatch):
    settings = Settings(
        environment="test",
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret-different",
        breakglass_jwt_secret_fallback_enabled=True,
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        oidc_session_jwt_secret=OIDC_SECRET,
        oidc_session_cookie_name=COOKIE,
        oidc_session_max_age=3600,
        sso_portal_default_realm_slug="ar-systems",
        oidc_native_session_enabled_realms="ar-systems",
    )
    get_settings.cache_clear()
    monkeypatch.setattr("app.oidc_bff.get_settings", lambda: settings)
    from app.main import app

    app.dependency_overrides[get_settings] = lambda: settings
    yield settings
    app.dependency_overrides.pop(get_settings, None)
    get_settings.cache_clear()


def _token_result(*, username: str = "alice") -> OidcTokenResult:
    return OidcTokenResult(
        access_token="access",
        refresh_token="refresh",
        id_token="id",
        expires_in=300,
        sub="kc-sub-1",
        preferred_username=username,
        claims={"sub": "kc-sub-1", "preferred_username": username},
    )


def _ok_step(*, username: str = "alice") -> LoginStepResult:
    return LoginStepResult(status="success", tokens=_token_result(username=username))


def test_oidc_login_success_sets_cookie_and_session(
    client: TestClient, db_session: Session, oidc_settings: Settings
):
    with patch(
        "app.oidc_bff.start_headless_login",
        new=AsyncMock(return_value=_ok_step()),
    ):
        response = client.post(
            "/auth/login",
            data={"username": "alice", "password": "secret"},
            headers={"X-Real-IP": "10.0.0.20"},
        )

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["username"] == "alice"
    assert COOKIE in response.cookies

    row = db_session.query(OidcSession).filter_by(sub="kc-sub-1").one()
    assert row.username == "alice"
    assert row.realm == "ar-systems"
    assert row.revoked is False

    claims = validate_oidc_session_cookie(
        response.cookies[COOKIE], db=db_session, settings=oidc_settings
    )
    assert claims is not None
    assert claims.jti == row.jti
    assert claims.sub == "kc-sub-1"

    audit = (
        db_session.query(AuditLog)
        .filter_by(action="oidc_login_success")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details.get("realm") == "ar-systems"
    assert "password" not in (audit.details or {})


def test_oidc_login_invalid_credentials_generic_401(
    client: TestClient, db_session: Session, oidc_settings: Settings
):
    with patch(
        "app.oidc_bff.start_headless_login",
        new=AsyncMock(side_effect=InvalidCredentialsError("bad")),
    ):
        response = client.post(
            "/auth/login",
            data={"username": "alice", "password": "wrong"},
            headers={"X-Real-IP": "10.0.0.21"},
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "Identifiants invalides."
    assert COOKIE not in response.cookies
    assert db_session.query(OidcSession).count() == 0


def test_oidc_login_mfa_also_generic_401(
    client: TestClient, db_session: Session, oidc_settings: Settings
):
    with patch(
        "app.oidc_bff.start_headless_login",
        new=AsyncMock(side_effect=UnsupportedAuthFlowError("MFA required")),
    ):
        response = client.post(
            "/auth/login",
            data={"username": "alice", "password": "secret"},
            headers={"X-Real-IP": "10.0.0.22"},
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "Identifiants invalides."
    audit = (
        db_session.query(AuditLog)
        .filter_by(action="oidc_login_unsupported_flow")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details.get("realm") == "ar-systems"
    assert "MFA" in (audit.details.get("detail") or "")


def test_html_unsupported_flow_shows_action_message(
    client: TestClient, db_session: Session, oidc_settings: Settings
):
    """HTML login must not masquerade required-action as invalid credentials."""
    with patch(
        "app.oidc_bff.start_headless_login",
        new=AsyncMock(
            side_effect=UnsupportedAuthFlowError(
                "Flux Keycloak non supporté en headless: required action après login"
            )
        ),
    ):
        response = client.post(
            "/auth/login",
            data={"username": "alice", "password": "secret", "rd": "/apps"},
            headers={"X-Real-IP": "10.0.0.23"},
        )

    assert response.status_code == 200
    assert "Identifiants invalides" not in response.text
    assert "action" in response.text.lower()
    assert "Keycloak" in response.text


def test_oidc_login_otp_required_json(
    client: TestClient, db_session: Session, oidc_settings: Settings
):
    with patch(
        "app.oidc_bff.start_headless_login",
        new=AsyncMock(
            return_value=LoginStepResult(status="otp_required", attempt_id="att-1")
        ),
    ):
        response = client.post(
            "/auth/login",
            data={"username": "alice", "password": "secret"},
            headers={"X-Real-IP": "10.0.0.24"},
        )
    assert response.status_code == 200
    assert response.json() == {"status": "otp_required", "attempt_id": "att-1"}
    audit = (
        db_session.query(AuditLog)
        .filter_by(action="oidc_login_otp_required")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None


def test_oidc_login_enabled_but_bff_config_missing_503(
    client: TestClient, db_session: Session, oidc_settings: Settings
):
    """Realm allowed via CSV but no RealmConfig BFF columns → 503, no silent fallback."""
    response = client.post(
        "/auth/login",
        data={"username": "alice", "password": "secret"},
        headers={"X-Real-IP": "10.0.0.23"},
    )
    assert response.status_code == 503
    assert "non configuré" in response.json()["detail"].lower()
    assert COOKIE not in response.cookies
    assert db_session.query(OidcSession).count() == 0


def test_oidc_login_rate_limit_429(
    client: TestClient, db_session: Session, oidc_settings: Settings
):
    with patch(
        "app.oidc_bff.start_headless_login",
        new=AsyncMock(side_effect=InvalidCredentialsError("bad")),
    ):
        for _ in range(OIDC_LOGIN_MAX_FAILURES):
            r = client.post(
                "/auth/login",
                data={"username": "bob", "password": "x"},
                headers={"X-Real-IP": "10.0.0.30"},
            )
            assert r.status_code == 401

        blocked = client.post(
            "/auth/login",
            data={"username": "bob", "password": "x"},
            headers={"X-Real-IP": "10.0.0.30"},
        )

    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


def test_validate_oidc_session_cookie_rejects_revoked(
    db_session: Session, oidc_settings: Settings
):
    token, jti = issue_oidc_session(
        db_session,
        sub="sub-1",
        username="alice",
        realm="ar-systems",
        secret=OIDC_SECRET,
        max_age=3600,
    )
    db_session.commit()

    assert validate_oidc_session_cookie(token, db=db_session, settings=oidc_settings)

    row = db_session.query(OidcSession).filter_by(jti=jti).one()
    row.revoked = True
    db_session.commit()

    assert (
        validate_oidc_session_cookie(token, db=db_session, settings=oidc_settings)
        is None
    )


def test_validate_oidc_session_cookie_rejects_expired(
    db_session: Session, oidc_settings: Settings
):
    jti = str(uuid4())
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "sub-1",
            "username": "alice",
            "realm": "ar-systems",
            "jti": jti,
            "iat": now - timedelta(hours=2),
            "exp": now - timedelta(hours=1),
            "type": "oidc",
        },
        OIDC_SECRET,
        algorithm="HS256",
    )
    db_session.add(
        OidcSession(
            jti=jti,
            sub="sub-1",
            username="alice",
            realm="ar-systems",
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
        )
    )
    db_session.commit()

    assert (
        validate_oidc_session_cookie(token, db=db_session, settings=oidc_settings)
        is None
    )


def test_oidc_logout_revokes_and_clears_cookie(
    client: TestClient, db_session: Session, oidc_settings: Settings
):
    with patch(
        "app.oidc_bff.start_headless_login",
        new=AsyncMock(return_value=_ok_step()),
    ):
        login = client.post(
            "/auth/login",
            data={"username": "alice", "password": "secret"},
            headers={"X-Real-IP": "10.0.0.40"},
        )
    assert login.status_code == 200
    cookie = login.cookies[COOKIE]
    client.cookies.set(COOKIE, cookie)
    row = db_session.query(OidcSession).one()
    assert row.revoked is False

    logout = client.post("/auth/logout")
    assert logout.status_code == 200

    db_session.refresh(row)
    assert row.revoked is True
    assert (
        validate_oidc_session_cookie(cookie, db=db_session, settings=oidc_settings)
        is None
    )


def test_portal_get_logout_clears_bastion_session(
    client: TestClient, db_session: Session, oidc_settings: Settings
):
    """User-menu link is GET /logout — must clear bastion_session (not only bg_session)."""
    with patch(
        "app.oidc_bff.start_headless_login",
        new=AsyncMock(return_value=_ok_step()),
    ):
        login = client.post(
            "/auth/login",
            data={"username": "alice", "password": "secret"},
            headers={"X-Real-IP": "10.0.0.40"},
        )
    assert login.status_code == 200
    cookie = login.cookies[COOKIE]
    client.cookies.set(COOKIE, cookie)
    row = db_session.query(OidcSession).one()
    assert row.revoked is False

    logout = client.get("/logout", follow_redirects=False)
    assert logout.status_code == 302
    assert logout.headers.get("location") == "/auth/login"
    set_cookie = " ".join(logout.headers.get_list("set-cookie")).lower()
    assert "bastion_session=" in set_cookie
    assert "max-age=0" in set_cookie or "expires=" in set_cookie

    db_session.refresh(row)
    assert row.revoked is True
    assert (
        validate_oidc_session_cookie(cookie, db=db_session, settings=oidc_settings)
        is None
    )
