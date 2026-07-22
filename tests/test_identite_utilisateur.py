"""identite_utilisateur — password-on-demand open flow."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.admin.throttling import (
    IDENTITY_MAX_FAILURES,
    reset_test_rate_limits,
)
from app.bastion.drivers.base import RoboticLoginError
from app.bastion.drivers.crushftp import CrushFTPSession
from app.bastion.bastion_fields import resolve_identity_login_username
from app.models import App, AppGroup, AuditLog, RBACGroup
from app.rbac.grants_service import AccessGrantCreate, create_grant
from app.robotic.impersonate_service import (
    ImpersonationIdentityAuthError,
    ImpersonationPasswordRequiredError,
    impersonate,
)
from app.sso_settings import Settings
from app.vault.app_credential_service import set_app_credential
from app.vault.user_app_credential_service import get_effective_credential

SECRET_PASSWORD = "IdentityPass-MustNotAppearInLogs-9xQ"
WRONG_PASSWORD = "WrongIdentityPass-MustNotAppear-7kZ"
SECRET_SHARED = "SharedVaultSecret-MustNotLeak"
KC_USER = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff0001"

USER_HEADERS = {
    "X-Email": "vincent.tisseront@ar-systems.fr",
    # Short preferred_username (Keycloak often sends local-part only)
    "X-Preferred-Username": "vincent.tisseront",
    "X-Groups": "transfer-users",
    "X-User-Id": KC_USER,
}

FULL_EMAIL = "vincent.tisseront@ar-systems.fr"


@pytest.fixture(autouse=True)
def _reset_throttle():
    reset_test_rate_limits()
    yield
    reset_test_rate_limits()


def _settings(**kwargs) -> Settings:
    defaults = {
        "vault_portal_internal_token": "test-secret",
        "portal_secret_encryption_key": "test-encryption-key-for-pytest-only",
        "database_url": "sqlite://",
        "subdomain_sso_enabled": False,
    }
    defaults.update(kwargs)
    return Settings(**defaults)


def _seed_app(db: Session, *, with_group: bool = True) -> App:
    app = App(
        slug="grommunio",
        label="Grommunio",
        upstream_url="https://mail.example/",
        robotic_driver="crushftp",
        access_mode="legacy_path_proxy",
        credential_mode="identite_utilisateur",
        enabled=True,
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    if with_group:
        group = RBACGroup(name="transfer-users")
        db.add(group)
        db.commit()
        db.refresh(group)
        db.add(AppGroup(app_id=app.id, group_id=group.id))
        db.commit()
    return app


@pytest.mark.asyncio
async def test_identity_mode_ignores_vault_shared(db_session: Session):
    _seed_app(db_session, with_group=False)
    settings = _settings()
    set_app_credential(db_session, "grommunio", "shared-robot", SECRET_SHARED, settings)

    row, source = get_effective_credential(db_session, "grommunio", KC_USER)
    assert row is None
    assert source is None


@pytest.mark.asyncio
async def test_impersonate_requires_ephemeral_password(db_session: Session):
    _seed_app(db_session, with_group=False)
    with pytest.raises(ImpersonationPasswordRequiredError):
        await impersonate(db_session, "grommunio", _settings(), actor="user@test")


@pytest.mark.asyncio
async def test_identity_login_failure_is_generic(db_session: Session, caplog):
    _seed_app(db_session, with_group=False)
    settings = _settings()

    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=AsyncMock(side_effect=RoboticLoginError("user unknown / bad password")),
        ),
        caplog.at_level(logging.DEBUG),
    ):
        with pytest.raises(ImpersonationIdentityAuthError) as exc_info:
            await impersonate(
                db_session,
                "grommunio",
                settings,
                actor="user@test",
                ephemeral_username="vincent.tisseront@ar-systems.fr",
                ephemeral_password=WRONG_PASSWORD,
            )

    assert "user unknown" not in str(exc_info.value).lower()
    assert WRONG_PASSWORD not in "\n".join(r.getMessage() for r in caplog.records)
    assert WRONG_PASSWORD not in str(exc_info.value)

    audit = (
        db_session.query(AuditLog)
        .filter_by(action="robotic.impersonate")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details["credential_mode"] == "identite_utilisateur"
    assert audit.details["success"] is False
    assert WRONG_PASSWORD not in str(audit.details)


def test_resolve_identity_login_username_prefers_email_by_default():
    assert (
        resolve_identity_login_username(
            email=FULL_EMAIL,
            username="vincent.tisseront",
            identity_format="email",
        )
        == FULL_EMAIL
    )
    assert (
        resolve_identity_login_username(
            email=FULL_EMAIL,
            username="vincent.tisseront",
            identity_format="username",
        )
        == "vincent.tisseront"
    )


def test_open_with_identity_uses_session_username_not_body(
    client: TestClient, db_session: Session
):
    _seed_app(db_session)
    fake_session = CrushFTPSession(
        cookies={"CrushAuth": "IDCOOKIE1234", "currentAuth": "abcd"},
        base_url="https://mail.example/",
    )
    login_mock = AsyncMock(return_value=fake_session)

    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=login_mock,
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.get_username",
            new=AsyncMock(return_value=FULL_EMAIL),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.logout",
            new=AsyncMock(),
        ),
    ):
        resp = client.post(
            "/api/apps/grommunio/open-with-identity",
            headers=USER_HEADERS,
            json={
                "password": SECRET_PASSWORD,
                "username": "attacker-spoofed@evil.example",
            },
            follow_redirects=False,
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["target_url"] == "/proxy/grommunio/"
    login_mock.assert_awaited_once()
    args = login_mock.await_args.args
    assert args[1] == FULL_EMAIL
    assert args[2] == SECRET_PASSWORD
    assert "attacker-spoofed" not in str(args)
    assert args[1] != "vincent.tisseront"  # must not use short preferred_username


def test_open_with_identity_password_absent_from_logs(
    client: TestClient, db_session: Session, caplog
):
    _seed_app(db_session)

    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=AsyncMock(side_effect=RoboticLoginError("rejected")),
        ),
        caplog.at_level(logging.DEBUG),
    ):
        resp = client.post(
            "/api/apps/grommunio/open-with-identity",
            headers=USER_HEADERS,
            json={"password": WRONG_PASSWORD},
            follow_redirects=False,
        )

    assert resp.status_code == 403
    body = resp.json()
    assert body["error"] == "identity_auth_failed"
    assert "Mot de passe incorrect" in body["message"]
    assert WRONG_PASSWORD not in body["message"]

    log_blob = "\n".join(r.getMessage() for r in caplog.records)
    assert WRONG_PASSWORD not in log_blob

    audits = db_session.query(AuditLog).all()
    for audit in audits:
        assert WRONG_PASSWORD not in str(audit.details)
        assert WRONG_PASSWORD not in (audit.actor or "")


def test_open_with_identity_rate_limit(client: TestClient, db_session: Session):
    _seed_app(db_session)

    with patch(
        "app.robotic.impersonate_service.CrushFTPDriver.login",
        new=AsyncMock(side_effect=RoboticLoginError("rejected")),
    ):
        for _ in range(IDENTITY_MAX_FAILURES):
            resp = client.post(
                "/api/apps/grommunio/open-with-identity",
                headers=USER_HEADERS,
                json={"password": WRONG_PASSWORD},
                follow_redirects=False,
            )
            assert resp.status_code == 403

        blocked = client.post(
            "/api/apps/grommunio/open-with-identity",
            headers=USER_HEADERS,
            json={"password": WRONG_PASSWORD},
            follow_redirects=False,
        )

    assert blocked.status_code == 429
    payload = blocked.json()
    assert payload["error"] == "too_many_attempts"
    assert "Retry-After" in blocked.headers

    audit = (
        db_session.query(AuditLog)
        .filter_by(action="robotic.impersonate.blocked_identity")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details["reason"] == "too_many_failed_identity_attempts"
    assert audit.details["credential_mode"] == "identite_utilisateur"
    assert WRONG_PASSWORD not in str(audit.details)


def test_open_with_identity_success_redirect_and_cookies(
    client: TestClient, db_session: Session
):
    _seed_app(db_session)
    fake_session = CrushFTPSession(
        cookies={"CrushAuth": "GOODCOOKIE99", "currentAuth": "99"},
        base_url="https://mail.example/",
    )

    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=AsyncMock(return_value=fake_session),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.get_username",
            new=AsyncMock(return_value=FULL_EMAIL),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.logout",
            new=AsyncMock(),
        ),
    ):
        resp = client.post(
            "/api/apps/grommunio/open-with-identity",
            headers=USER_HEADERS,
            json={"password": SECRET_PASSWORD},
            follow_redirects=False,
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["target_url"] == "/proxy/grommunio/"
    set_cookie = resp.headers.get("set-cookie", "")
    # CrushFTP cookies may be split across multiple Set-Cookie headers
    cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [set_cookie]
    joined = " ".join(cookie_headers)
    assert "CrushAuth" in joined or "GOODCOOKIE99" in joined or "crush" in joined.lower() or resp.cookies

    audit = (
        db_session.query(AuditLog)
        .filter_by(action="robotic.impersonate")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details["success"] is True
    assert audit.details["credential_mode"] == "identite_utilisateur"
    assert audit.details["credential_source"] == "user_identity"
    assert SECRET_PASSWORD not in str(audit.details)


def test_open_with_identity_unauthenticated_returns_401(
    client: TestClient, db_session: Session
):
    """Without SSO headers, require_user → 401 JSON (no HTML login — that's Nginx)."""
    _seed_app(db_session)
    resp = client.post(
        "/api/apps/grommunio/open-with-identity",
        json={"password": SECRET_PASSWORD},
        follow_redirects=False,
    )
    assert resp.status_code == 401
    assert resp.headers.get("content-type", "").startswith("application/json")
    assert "Authentication required" in str(resp.json().get("detail", ""))


def test_open_with_identity_authenticated_wrong_password_is_json_403_not_login_redirect(
    client: TestClient, db_session: Session
):
    """Wrong app password must stay JSON 403 — never look like a dead portal session."""
    _seed_app(db_session)
    with patch(
        "app.robotic.impersonate_service.CrushFTPDriver.login",
        new=AsyncMock(side_effect=RoboticLoginError("rejected")),
    ):
        resp = client.post(
            "/api/apps/grommunio/open-with-identity",
            headers=USER_HEADERS,
            json={"password": WRONG_PASSWORD},
            follow_redirects=False,
        )
    assert resp.status_code == 403
    assert resp.headers.get("content-type", "").startswith("application/json")
    assert resp.json()["error"] == "identity_auth_failed"
    assert "/auth/login" not in (resp.headers.get("location") or "")


def test_get_impersonate_rejected_for_identity_mode(
    client: TestClient, db_session: Session
):
    _seed_app(db_session)
    resp = client.get(
        "/api/internal/impersonate/grommunio",
        headers=USER_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "password_required"


def test_portal_identity_tile_has_no_impersonate_href(
    client: TestClient, db_session: Session
):
    """Catalogue tile must POST open-with-identity — never link to impersonate."""
    app = _seed_app(db_session)
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id=KC_USER,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db_session.commit()

    resp = client.get("/apps", headers=USER_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    assert "data-open-with-identity" in html
    assert 'data-open-identity-url="/api/apps/grommunio/open-with-identity"' in html
    assert 'data-credential-mode="identite_utilisateur"' in html
    assert f'data-identity-username="{FULL_EMAIL}"' in html
    assert 'data-identity-username="vincent.tisseront"' not in html
    assert "/api/internal/impersonate/grommunio" not in html
    assert 'href="/api/internal/impersonate/grommunio"' not in html
    assert "bastionPasswordPrompt" in html
