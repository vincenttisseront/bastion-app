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
    logout_mock = AsyncMock()
    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=AsyncMock(return_value=fake_session),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.get_username",
            new=AsyncMock(return_value="robot"),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.logout",
            new=logout_mock,
        ),
        caplog.at_level(logging.DEBUG),
    ):
        result = await impersonate(db_session, "transfer", settings, actor="user@test")

    assert result.cookies["CrushAuth"] == "ABCDEFGH1234"
    assert result.target_url == "/proxy/transfer/"
    assert result.mode == "legacy"
    logout_mock.assert_not_awaited()

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

    logout_mock = AsyncMock()
    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=AsyncMock(side_effect=RoboticLoginError("CrushFTP login rejected")),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.logout",
            new=logout_mock,
        ),
    ):
        with pytest.raises(ImpersonationError, match="rejected"):
            await impersonate(db_session, "transfer", settings)

    logout_mock.assert_not_awaited()
    audit = (
        db_session.query(AuditLog)
        .filter_by(action="robotic.impersonate")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details["success"] is False
    assert SECRET_PASSWORD not in str(audit.details)


@pytest.mark.asyncio
async def test_impersonate_logout_on_identity_mismatch(db_session: Session):
    _make_crush_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "robot", SECRET_PASSWORD, settings)

    fake_session = CrushFTPSession(
        cookies={"CrushAuth": "MISMATCHCOOKIE1", "currentAuth": "1234"},
        base_url="https://crush.example/",
    )
    logout_mock = AsyncMock()
    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=AsyncMock(return_value=fake_session),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.get_username",
            new=AsyncMock(return_value="other-user"),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.logout",
            new=logout_mock,
        ),
    ):
        with pytest.raises(ImpersonationError, match="fingerprint mismatch"):
            await impersonate(db_session, "transfer", settings, actor="user@test")

    logout_mock.assert_awaited_once_with(fake_session)


@pytest.mark.asyncio
async def test_impersonate_logout_on_get_username_failure(db_session: Session):
    _make_crush_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "robot", SECRET_PASSWORD, settings)

    fake_session = CrushFTPSession(
        cookies={"CrushAuth": "GETUSERFAIL1234", "currentAuth": "1234"},
        base_url="https://crush.example/",
    )
    logout_mock = AsyncMock()
    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=AsyncMock(return_value=fake_session),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.get_username",
            new=AsyncMock(side_effect=RoboticLoginError("CrushFTP getUsername rejected")),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.logout",
            new=logout_mock,
        ),
    ):
        with pytest.raises(ImpersonationError, match="getUsername"):
            await impersonate(db_session, "transfer", settings, actor="user@test")

    logout_mock.assert_awaited_once_with(fake_session)


@pytest.mark.asyncio
async def test_impersonate_logout_on_resolve_target_failure(db_session: Session):
    _make_crush_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "robot", SECRET_PASSWORD, settings)

    fake_session = CrushFTPSession(
        cookies={"CrushAuth": "RESOLVEFAIL1234", "currentAuth": "1234"},
        base_url="https://crush.example/",
    )
    logout_mock = AsyncMock()
    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=AsyncMock(return_value=fake_session),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.get_username",
            new=AsyncMock(return_value="robot"),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.logout",
            new=logout_mock,
        ),
        patch(
            "app.robotic.impersonate_service._resolve_target",
            side_effect=RuntimeError("db boom"),
        ),
    ):
        with pytest.raises(RuntimeError, match="db boom"):
            await impersonate(db_session, "transfer", settings, actor="user@test")

    logout_mock.assert_awaited_once_with(fake_session)


@pytest.mark.asyncio
async def test_crushftp_subdomain_login_uses_upstream_with_public_host(
    db_session: Session,
):
    """Robotic login must hit upstream (bypass SSO) with Host=public FQDN."""
    app = App(
        slug="transfer",
        label="Transfer",
        upstream_url="https://172.24.0.106/",
        public_fqdn="transfer.ar-systems.fr",
        robotic_driver="crushftp",
        access_mode="subdomain_proxy",
        enabled=True,
    )
    db_session.add(app)
    db_session.commit()
    settings = _settings(subdomain_sso_enabled=True, portal_domain="portal.ar-systems.fr")
    set_app_credential(db_session, "transfer", "robot", SECRET_PASSWORD, settings)

    fake_session = CrushFTPSession(
        cookies={"CrushAuth": "FQDNCOOKIE1234", "currentAuth": "1234"},
        base_url="https://172.24.0.106/",
        request_headers={"Host": "transfer.ar-systems.fr"},
    )
    login_mock = AsyncMock(return_value=fake_session)
    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=login_mock,
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.get_username",
            new=AsyncMock(return_value="robot"),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.logout",
            new=AsyncMock(),
        ),
    ):
        result = await impersonate(db_session, "transfer", settings, actor="user@test")

    login_mock.assert_awaited_once()
    assert login_mock.await_args.args[0] == "https://172.24.0.106/"
    assert login_mock.await_args.kwargs.get("extra_headers", {}).get("Host") == (
        "transfer.ar-systems.fr"
    )
    assert result.mode == "subdomain"
    assert result.target_url == "https://transfer.ar-systems.fr/"
    assert result.login_base_url == "https://172.24.0.106/"


@pytest.mark.asyncio
async def test_crushftp_subdomain_login_prefers_admin_api_when_upstream_is_public(
    db_session: Session,
):
    app = App(
        slug="transfer",
        label="Transfer",
        upstream_url="https://transfer.ar-systems.fr/",
        public_fqdn="transfer.ar-systems.fr",
        crushftp_admin_base_url="https://172.24.0.106:8080/",
        robotic_driver="crushftp",
        access_mode="subdomain_proxy",
        enabled=True,
    )
    db_session.add(app)
    db_session.commit()
    settings = _settings(subdomain_sso_enabled=True, portal_domain="portal.ar-systems.fr")
    set_app_credential(db_session, "transfer", "robot", SECRET_PASSWORD, settings)

    fake_session = CrushFTPSession(
        cookies={"CrushAuth": "ADMINBASE1234", "currentAuth": "1234"},
        base_url="https://172.24.0.106:8080/",
    )
    login_mock = AsyncMock(return_value=fake_session)
    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=login_mock,
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.get_username",
            new=AsyncMock(return_value="robot"),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.logout",
            new=AsyncMock(),
        ),
    ):
        result = await impersonate(db_session, "transfer", settings, actor="user@test")

    assert login_mock.await_args.args[0] == "https://172.24.0.106:8080/"
    assert result.login_base_url == "https://172.24.0.106:8080/"
