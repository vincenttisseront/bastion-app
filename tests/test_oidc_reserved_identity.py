"""Password / OTP native login refuses the reserved ``@breakglass.local`` domain.

That domain belongs to the local break-glass accounts (``/breakglass/login``).
An IdP identity carrying it — typed login, Keycloak username or e-mail — must
never receive a ``bastion_session``: upstream apps behind ``auth_request`` would
see the reserved identity in their headers before ``user_context`` rejects it.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth.oidc_bff import (
    NativeLoginIdentity,
    ReservedIdentityError,
    finalize_native_login,
    is_reserved_identity,
)
from app.auth.oidc_bff_client import LoginStepResult, OidcTokenResult
from app.models import AuditLog, OidcSession
from app.security.banning.engine import RULE_FAILED_LOGIN, find_active_ban
from app.sso_settings import Settings, get_settings
from app.testing_framework.throttle import reset_throttles

OIDC_SECRET = "oidc-session-hmac-key-32bytes-min!!"
COOKIE = "bastion_session"

PUBLIC_IP = "203.0.113.50"


@pytest.fixture(autouse=True)
def _reset_rate_limits():
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
        sso_portal_default_realm_slug="default",
        oidc_native_session_enabled_realms="default",
    )
    get_settings.cache_clear()
    monkeypatch.setattr("app.auth.oidc_bff.get_settings", lambda: settings)
    from app.main import app

    app.dependency_overrides[get_settings] = lambda: settings
    yield settings
    app.dependency_overrides.pop(get_settings, None)
    get_settings.cache_clear()


def _step(*, username: str, email: str | None = None) -> LoginStepResult:
    return LoginStepResult(
        status="success",
        tokens=OidcTokenResult(
            access_token="access",
            refresh_token="refresh",
            id_token="id",
            expires_in=300,
            sub="kc-sub-rsv",
            preferred_username=username,
            email=email,
            claims={"sub": "kc-sub-rsv", "preferred_username": username},
        ),
    )


def _assert_refused(response, db_session: Session) -> None:
    assert response.status_code == 401
    assert response.json()["message"] == "Identifiants invalides."
    assert COOKIE not in response.cookies
    assert db_session.query(OidcSession).count() == 0
    audit = (
        db_session.query(AuditLog)
        .filter_by(action="oidc_login_failed")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details.get("reason") == "reserved_identity_domain"
    assert db_session.query(AuditLog).filter_by(action="oidc_login_success").count() == 0


@pytest.mark.parametrize(
    "value",
    ["root@breakglass.local", "ROOT@BreakGlass.Local", "  admin@breakglass.local  "],
)
def test_is_reserved_identity(value: str):
    assert is_reserved_identity(None, value)
    assert not is_reserved_identity("alice", "alice@example.com", None, "")
    assert not is_reserved_identity("alice@breakglass.local.example.com")


def test_typed_reserved_login_refused_before_keycloak(
    client: TestClient, db_session: Session, oidc_settings: Settings
):
    kc = AsyncMock(return_value=_step(username="root@breakglass.local"))
    with patch("app.auth.oidc_bff.start_headless_login", new=kc):
        response = client.post(
            "/auth/login",
            data={"username": "root@breakglass.local", "password": "secret"},
            headers={"X-Real-IP": PUBLIC_IP},
        )
    _assert_refused(response, db_session)
    kc.assert_not_called()


@pytest.mark.parametrize(
    ("username", "email"),
    [
        ("root@breakglass.local", None),  # Keycloak username renamed
        ("alice", "alice@breakglass.local"),  # e-mail set to the reserved domain
    ],
)
def test_keycloak_reserved_identity_refused(
    client: TestClient,
    db_session: Session,
    oidc_settings: Settings,
    username: str,
    email: str | None,
):
    with patch(
        "app.auth.oidc_bff.start_headless_login",
        new=AsyncMock(return_value=_step(username=username, email=email)),
    ):
        response = client.post(
            "/auth/login",
            data={"username": "alice", "password": "secret"},
            headers={"X-Real-IP": PUBLIC_IP},
        )
    _assert_refused(response, db_session)


def test_reserved_identity_after_otp_refused(
    client: TestClient, db_session: Session, oidc_settings: Settings
):
    with patch(
        "app.auth.oidc_bff.submit_headless_otp",
        new=AsyncMock(return_value=_step(username="alice", email="ops@breakglass.local")),
    ):
        response = client.post(
            "/auth/login",
            data={"username": "alice", "attempt_id": "att-1", "otp_code": "123456"},
            headers={"X-Real-IP": PUBLIC_IP},
        )
    _assert_refused(response, db_session)


def test_html_reserved_identity_shows_generic_error(
    client: TestClient, db_session: Session, oidc_settings: Settings
):
    with (
        patch(
            "app.auth.oidc_bff.start_headless_login",
            new=AsyncMock(return_value=_step(username="root@breakglass.local")),
        ),
        patch("app.auth.oidc_bff.verify_csrf_token", return_value=True),
    ):
        response = client.post(
            "/auth/login",
            data={"username": "alice", "password": "secret", "csrf_token": "x", "rd": "/apps"},
            headers={"X-Real-IP": PUBLIC_IP, "Accept": "text/html"},
        )
    assert response.status_code == 200
    assert "Identifiants invalides." in response.text
    assert COOKIE not in response.cookies
    assert db_session.query(OidcSession).count() == 0


def test_reserved_identity_attempts_feed_ban_engine(
    client: TestClient, db_session: Session, oidc_settings: Settings
):
    from app.security.banning.service import update_ban_rules

    update_ban_rules(
        db_session,
        rules={
            RULE_FAILED_LOGIN: {
                "enabled": True,
                "threshold": 2,
                "window_seconds": 60,
                "ban_minutes": 10,
                "ban_username": True,
            }
        },
        actor="test",
    )
    with patch(
        "app.auth.oidc_bff.start_headless_login",
        new=AsyncMock(return_value=_step(username="root@breakglass.local")),
    ):
        first = client.post(
            "/auth/login",
            data={"username": "alice", "password": "secret"},
            headers={"X-Real-IP": PUBLIC_IP},
        )
        second = client.post(
            "/auth/login",
            data={"username": "alice", "password": "secret"},
            headers={"X-Real-IP": PUBLIC_IP},
        )
    assert first.status_code == 401
    assert second.status_code == 403
    assert find_active_ban(db_session, username="alice") is not None
    # A clean identity stays blocked while the ban is active.
    with patch(
        "app.auth.oidc_bff.start_headless_login",
        new=AsyncMock(return_value=_step(username="alice")),
    ):
        third = client.post(
            "/auth/login",
            data={"username": "alice", "password": "secret"},
            headers={"X-Real-IP": PUBLIC_IP},
        )
    assert third.status_code == 403
    assert db_session.query(OidcSession).count() == 0


@pytest.mark.parametrize(
    ("username", "email", "login_username"),
    [
        ("root@breakglass.local", None, "root"),
        ("alice", "alice@breakglass.local", "alice"),
        ("alice", None, "x@breakglass.local"),
    ],
)
def test_finalize_native_login_fails_closed(
    db_session: Session,
    oidc_settings: Settings,
    username: str,
    email: str | None,
    login_username: str,
):
    identity = NativeLoginIdentity(
        sub="kc-sub-rsv",
        username=username,
        email=email,
        groups=(),
        realm_slug="default",
    )
    with pytest.raises(ReservedIdentityError):
        finalize_native_login(
            db_session,
            oidc_settings,
            identity,
            secret=OIDC_SECRET,
            client_ip=PUBLIC_IP,
            login_username=login_username,
            safe_rd="/apps",
            html_mode=False,
            audit_action="oidc_login_success",
        )
    assert db_session.query(OidcSession).count() == 0
