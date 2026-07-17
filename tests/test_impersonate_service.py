"""Impersonation service tests."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.orm import Session

from app.bastion.drivers.base import RoboticLoginError
from app.bastion.drivers.crushftp import CrushFTPSession
from app.models import App, AuditLog
from app.robotic.impersonate_service import ImpersonationError, impersonate
from app.sso_settings import Settings
from app.vault.app_credential_service import set_app_credential

SECRET_PASSWORD = "VaultPlainPassword-MustNotLeak"


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
    db.refresh(app)
    return app


@pytest.mark.asyncio
async def test_robotic_impersonate_success(db_session: Session, caplog):
    _make_crush_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "robot", SECRET_PASSWORD, settings)

    fake_session = CrushFTPSession(
        cookies={"CrushAuth": "ABCDEFGH1234", "currentAuth": "1234"},
        base_url="https://crush.example/",
    )
    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=AsyncMock(return_value=fake_session),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.get_username",
            new=AsyncMock(return_value="robot"),
        ),
        caplog.at_level(logging.DEBUG),
    ):
        result = await impersonate(db_session, "transfer", settings, actor="user@test")

    assert result.cookies["CrushAuth"] == "ABCDEFGH1234"
    assert result.target_url == "/proxy/transfer/"
    assert result.mode == "legacy"

    audit = (
        db_session.query(AuditLog)
        .filter_by(action="robotic.impersonate")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details["success"] is True
    blob = f"{audit.details}"
    assert SECRET_PASSWORD not in blob
    assert "ABCDEFGH1234" not in blob
    assert SECRET_PASSWORD not in "\n".join(r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_robotic_impersonate_missing_credential(db_session: Session):
    _make_crush_app(db_session)
    settings = _settings()
    with pytest.raises(ImpersonationError, match="credential"):
        await impersonate(db_session, "transfer", settings)


@pytest.mark.asyncio
async def test_robotic_impersonate_login_failure(db_session: Session):
    _make_crush_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "robot", SECRET_PASSWORD, settings)

    with patch(
        "app.robotic.impersonate_service.CrushFTPDriver.login",
        new=AsyncMock(side_effect=RoboticLoginError("CrushFTP login rejected")),
    ):
        with pytest.raises(ImpersonationError, match="rejected"):
            await impersonate(db_session, "transfer", settings)

    audit = (
        db_session.query(AuditLog)
        .filter_by(action="robotic.impersonate")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details["success"] is False
    assert SECRET_PASSWORD not in str(audit.details)
