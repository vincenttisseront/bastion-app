"""F-04: subdomain RFC1918 bypass disabled by default (aligned with portal)."""

from __future__ import annotations

import asyncio
import inspect
from unittest.mock import MagicMock

from app.sso_settings import Settings
from app.subdomain import subdomain_auth as mod
from app.subdomain.subdomain_auth import subdomain_auth


def test_settings_default_rfc1918_bypass_disabled():
    """Field default is False even if a local .env enables the flag for dev."""
    assert Settings.model_fields["rfc1918_bypass_enabled"].default is False


def test_subdomain_rfc1918_honours_settings_flag():
    src = inspect.getsource(mod.subdomain_auth)
    assert "settings.rfc1918_bypass_enabled" in src
    assert "F-04" in src or "2026-07-25" in src


def test_subdomain_lan_ip_does_not_bypass_when_flag_default_off(db_session):
    """Trusted proxy + RFC1918 client IP must still require SSO when flag is off."""
    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
        rfc1918_bypass_enabled=False,
        environment="test",
        session_hop_secret="test-session-hop-secret-for-pytest",
    )
    request = MagicMock()
    request.headers = {
        "X-Original-Host": "transfer.example.test",
        "X-Real-IP": "192.168.1.50",
    }
    request.client = MagicMock(host="10.5.0.2")

    resp = asyncio.run(subdomain_auth(request, db=db_session, settings=settings))
    assert resp.headers.get("X-Auth-Source") != "rfc1918-bypass"
    assert resp.status_code in (401, 403)
