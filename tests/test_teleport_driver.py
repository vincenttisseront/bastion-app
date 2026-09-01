"""Tests for Teleport robotic SSO driver."""

from __future__ import annotations

import httpx
import pytest
import respx
from httpx import Response
from sqlalchemy.orm import Session

from app.bastion.drivers.base import RoboticLoginError
from app.bastion.drivers.teleport import (
    TeleportDriver,
    resolve_teleport_login_base_url,
)
from app.models import App
from app.robotic.impersonate_service import impersonate
from app.sso_settings import Settings
from app.vault.app_credential_service import set_app_credential

BASE = "https://teleport.internal:3080"
LOGIN_URL = f"{BASE}/v1/webapi/sessions/web"
SECRET = "TeleportVaultSecret-DoNotLog"


def _settings(**kwargs) -> Settings:
    defaults = {
        "vault_portal_internal_token": "test-secret",
        "portal_secret_encryption_key": "test-encryption-key-for-pytest-only",
        "database_url": "sqlite://",
        "portal_domain": "portal.example.test",
        "subdomain_sso_enabled": True,
    }
    defaults.update(kwargs)
    return Settings(**defaults)


def _teleport_app(db: Session) -> App:
    app = App(
        slug="teleport",
        label="Teleport",
        upstream_url="https://teleport.internal:3080",
        public_fqdn="teleport.example.test",
        access_mode="subdomain_proxy",
        auth_mode="teleport",
        robotic_driver="teleport",
        enabled=True,
    )
    db.add(app)
    db.commit()
    return app


@pytest.mark.asyncio
@respx.mock
async def test_teleport_driver_login_sets_session_cookie():
    respx.post(LOGIN_URL).mock(
        return_value=Response(
            200,
            json={"type": "bearer", "token": "ignored-if-cookie"},
            headers={"Set-Cookie": "__Host-grv_session=sess-abc123; Path=/; Secure; HttpOnly"},
        )
    )
    driver = TeleportDriver()
    session = await driver.login(BASE, "admin", "pass", tls_verify=False)
    assert session.cookies["__Host-grv_session"] == "sess-abc123"
    assert await driver.get_username(session) == "admin"


@pytest.mark.asyncio
@respx.mock
async def test_teleport_driver_rejects_mfa():
    respx.post(LOGIN_URL).mock(
        return_value=Response(
            403,
            json={"error": {"message": "second factor token required"}},
        )
    )
    driver = TeleportDriver()
    with pytest.raises(RoboticLoginError) as exc_info:
        await driver.login(BASE, "admin", "pass", tls_verify=False)
    assert "second facteur" in str(exc_info.value).lower() or "mfa" in str(
        exc_info.value
    ).lower()


@pytest.mark.asyncio
@respx.mock
async def test_teleport_driver_rejects_html_sso_redirect():
    respx.post(LOGIN_URL).mock(
        return_value=Response(
            302,
            headers={"Location": "https://portal.example.test/auth/login"},
        )
    )
    driver = TeleportDriver()
    with pytest.raises(RoboticLoginError) as exc_info:
        await driver.login(BASE, "admin", "pass", tls_verify=False)
    assert "redirect" in str(exc_info.value).lower()


def test_resolve_teleport_login_base_url_rejects_public_fqdn(db_session: Session):
    app = App(
        slug="teleport",
        label="Teleport",
        upstream_url="https://teleport.example.test",
        public_fqdn="teleport.example.test",
        access_mode="subdomain_proxy",
        robotic_driver="teleport",
        enabled=True,
    )
    settings = _settings()
    with pytest.raises(ValueError) as exc_info:
        resolve_teleport_login_base_url(app, settings)
    assert "interne" in str(exc_info.value).lower()


def test_resolve_teleport_login_base_url_accepts_internal(db_session: Session):
    app = App(
        slug="teleport",
        label="Teleport",
        upstream_url="https://10.0.0.5:3080",
        public_fqdn="teleport.example.test",
        access_mode="subdomain_proxy",
        robotic_driver="teleport",
        enabled=True,
    )
    settings = _settings()
    assert resolve_teleport_login_base_url(app, settings) == "https://10.0.0.5:3080"


@pytest.mark.asyncio
@respx.mock
async def test_impersonate_teleport(db_session: Session):
    app = _teleport_app(db_session)
    settings = _settings()
    set_app_credential(db_session, app.slug, "admin", SECRET, settings)

    respx.post(LOGIN_URL).mock(
        return_value=Response(
            200,
            json={"type": "bearer", "token": "x"},
            headers={"Set-Cookie": "__Host-grv_session=sess-teleport; Path=/; Secure; HttpOnly"},
        )
    )

    result = await impersonate(
        db_session,
        app.slug,
        settings,
        actor="admin@test",
    )
    assert result.driver == "teleport"
    assert result.cookies["__Host-grv_session"] == "sess-teleport"
    assert result.target_url == "https://teleport.example.test/web/"
    assert result.fqdn == "teleport.example.test"
