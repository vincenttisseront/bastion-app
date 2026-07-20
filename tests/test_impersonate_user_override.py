"""Impersonation uses user vault override when present."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.orm import Session

from app.bastion.drivers.crushftp import CrushFTPSession
from app.models import App, AuditLog
from app.robotic.impersonate_service import impersonate
from app.sso_settings import Settings
from app.vault.app_credential_service import set_app_credential
from app.vault.user_app_credential_service import set_user_credential

SECRET_SHARED = "ImpSharedSecret-MustNotLeak"
SECRET_USER = "ImpUserOverride-MustNotLeak"
KC_USER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _settings(**kwargs) -> Settings:
    defaults = {
        "vault_portal_internal_token": "test-secret",
        "portal_secret_encryption_key": "test-encryption-key-for-pytest-only",
        "database_url": "sqlite://",
        "subdomain_sso_enabled": False,
    }
    defaults.update(kwargs)
    return Settings(**defaults)


def _make_crush_app(db: Session) -> App:
    app = App(
        slug="transfer",
        label="Transfer",
        upstream_url="https://crush.example/",
        robotic_driver="crushftp",
        access_mode="legacy_path_proxy",
        enabled=True,
    )
    db.add(app)
    db.commit()
    return app


@pytest.mark.asyncio
async def test_impersonate_uses_shared_without_override(db_session: Session, caplog):
    _make_crush_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "shared-robot", SECRET_SHARED, settings)

    fake = CrushFTPSession(
        cookies={"CrushAuth": "ABCDEFGH1234", "currentAuth": "1234"},
        base_url="https://crush.example/",
    )
    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=AsyncMock(return_value=fake),
        ) as login_mock,
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.get_username",
            new=AsyncMock(return_value="shared-robot"),
        ),
        caplog.at_level(logging.DEBUG),
    ):
        result = await impersonate(
            db_session,
            "transfer",
            settings,
            actor="user@test",
            keycloak_user_id=KC_USER,
        )

    assert result.credential_source == "shared"
    assert result.robotic_username == "shared-robot"
    assert login_mock.await_args.args[1] == "shared-robot"
    assert login_mock.await_args.args[2] == SECRET_SHARED

    audit = (
        db_session.query(AuditLog)
        .filter_by(action="robotic.impersonate")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details["credential_source"] == "shared"
    assert SECRET_SHARED not in str(audit.details)
    assert SECRET_USER not in "\n".join(r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_impersonate_uses_user_override(db_session: Session, caplog):
    _make_crush_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "shared-robot", SECRET_SHARED, settings)
    set_user_credential(
        db_session, "transfer", KC_USER, "user-robot", SECRET_USER, settings
    )

    fake = CrushFTPSession(
        cookies={"CrushAuth": "USERCOOKIE1234", "currentAuth": "1234"},
        base_url="https://crush.example/",
    )
    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=AsyncMock(return_value=fake),
        ) as login_mock,
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.get_username",
            new=AsyncMock(return_value="user-robot"),
        ),
        caplog.at_level(logging.DEBUG),
    ):
        result = await impersonate(
            db_session,
            "transfer",
            settings,
            actor="user@test",
            keycloak_user_id=KC_USER,
        )

    assert result.credential_source == "user_override"
    assert result.robotic_username == "user-robot"
    assert login_mock.await_args.args[1] == "user-robot"
    assert login_mock.await_args.args[2] == SECRET_USER

    audit = (
        db_session.query(AuditLog)
        .filter_by(action="robotic.impersonate")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details["credential_source"] == "user_override"
    assert SECRET_USER not in str(audit.details)
    assert SECRET_SHARED not in str(audit.details)
