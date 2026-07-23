"""Impersonate 409 when individual_required and no user override."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.admin.throttling import reset_test_rate_limits
from app.bastion.drivers.crushftp import CrushFTPSession
from app.models import App, AuditLog, RBACGroup
from app.robotic.impersonate_service import (
    ImpersonationCredentialRequiredError,
    impersonate,
)
from app.sso_settings import Settings
from app.vault.app_credential_service import set_app_credential
from app.vault.user_app_credential_service import set_user_credential
from app.rbac.grants_service import AccessGrantCreate, create_grant

SECRET_SHARED = "CredReqShared-MustNotLeak"
SECRET_USER = "CredReqUser-MustNotLeak"
KC_USER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

USER_HEADERS = {
    "X-Email": "user@example.com",
    "X-Groups": "transfer-users",
    "X-User-Id": KC_USER,
}


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


def _seed_app(
    db: Session,
    *,
    credential_mode: str = "individual_required",
    with_group: bool = True,
) -> App:
    app = App(
        slug="transfer",
        label="Transfer",
        upstream_url="https://crush.example/",
        robotic_driver="crushftp",
        access_mode="legacy_path_proxy",
        credential_mode=credential_mode,
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
        create_grant(
            db,
            AccessGrantCreate(
                subject_type="group",
                rbac_group_id=group.id,
                resource_type="application",
                application_id=app.id,
                access_level="launch",
            ),
            granted_by="test",
        )
        db.commit()
    return app


@pytest.mark.asyncio
async def test_impersonate_service_raises_credential_required(db_session: Session):
    _seed_app(db_session, with_group=False)
    settings = _settings()
    set_app_credential(db_session, "transfer", "shared-robot", SECRET_SHARED, settings)

    with pytest.raises(ImpersonationCredentialRequiredError):
        await impersonate(
            db_session,
            "transfer",
            settings,
            actor="user@test",
            keycloak_user_id=KC_USER,
        )

    audit = (
        db_session.query(AuditLog)
        .filter_by(action="robotic.impersonate.blocked_no_credential")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details["error"] == "credential_required"
    assert audit.details["app_slug"] == "transfer"
    assert audit.details["keycloak_user_id"] == KC_USER
    assert SECRET_SHARED not in str(audit.details)


def test_impersonate_route_409_without_override(client: TestClient, db_session: Session):
    _seed_app(db_session)
    set_app_credential(db_session, "transfer", "shared-robot", SECRET_SHARED, _settings())

    resp = client.get(
        "/api/internal/impersonate/transfer",
        headers=USER_HEADERS,
        follow_redirects=False,
    )

    assert resp.status_code == 409
    body = resp.json()
    assert body == {
        "error": "credential_required",
        "message": ImpersonationCredentialRequiredError.user_message,
    }
    assert "shared" not in resp.text.lower()
    assert SECRET_SHARED not in resp.text

    audit = (
        db_session.query(AuditLog)
        .filter_by(action="robotic.impersonate.blocked_no_credential")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert SECRET_SHARED not in str(audit.details)


def test_impersonate_route_302_with_override(client: TestClient, db_session: Session):
    _seed_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "shared-robot", SECRET_SHARED, settings)
    set_user_credential(
        db_session, "transfer", KC_USER, "user-robot", SECRET_USER, settings
    )

    fake_session = CrushFTPSession(
        cookies={"CrushAuth": "USERCOOKIE1234", "currentAuth": "1234"},
        base_url="https://crush.example/",
    )
    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=AsyncMock(return_value=fake_session),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.get_username",
            new=AsyncMock(return_value="user-robot"),
        ),
    ):
        resp = client.get(
            "/api/internal/impersonate/transfer",
            headers=USER_HEADERS,
            follow_redirects=False,
        )

    assert resp.status_code == 302
    assert resp.headers["location"] == "/proxy/transfer/"
    assert SECRET_USER not in resp.text
    assert SECRET_SHARED not in resp.text
