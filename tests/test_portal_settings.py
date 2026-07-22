"""Portal settings — subdomain_sso_enabled DB toggle with env fallback."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import App, AuditLog, PortalSettings
from app.portal_settings_service import (
    ensure_portal_settings,
    get_subdomain_sso_enabled,
    parse_subdomain_sso_env,
    set_subdomain_sso_enabled,
)
from app.robotic.impersonate_service import _resolve_target
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _settings(**kwargs) -> Settings:
    defaults = {
        "vault_portal_internal_token": "test-secret",
        "portal_secret_encryption_key": "test-encryption-key-for-pytest-only",
        "database_url": "sqlite://",
        "subdomain_sso_enabled": False,
    }
    defaults.update(kwargs)
    return Settings(**defaults)


def test_parse_subdomain_sso_env_from_monkeypatch(monkeypatch):
    monkeypatch.setenv("SUBDOMAIN_SSO_ENABLED", "true")
    assert parse_subdomain_sso_env() is True
    monkeypatch.setenv("SUBDOMAIN_SSO_ENABLED", "false")
    assert parse_subdomain_sso_env() is False
    monkeypatch.delenv("SUBDOMAIN_SSO_ENABLED", raising=False)
    assert parse_subdomain_sso_env({"SUBDOMAIN_SSO_ENABLED": "1"}) is True
    assert parse_subdomain_sso_env({}) is False


def test_migration_seed_matches_env(monkeypatch, db_session: Session):
    """Simulate migration seed: initial row mirrors SUBDOMAIN_SSO_ENABLED."""
    monkeypatch.setenv("SUBDOMAIN_SSO_ENABLED", "true")
    seeded = parse_subdomain_sso_env()
    assert seeded is True
    row = PortalSettings(
        id=1,
        subdomain_sso_enabled=seeded,
    )
    db_session.add(row)
    db_session.commit()

    settings = _settings(subdomain_sso_enabled=False)  # env Settings may differ in tests
    assert get_subdomain_sso_enabled(db_session, settings) is True


def test_fallback_to_settings_when_row_missing(db_session: Session):
    assert db_session.query(PortalSettings).count() == 0
    settings_off = _settings(subdomain_sso_enabled=False)
    assert get_subdomain_sso_enabled(db_session, settings_off) is False
    settings_on = _settings(subdomain_sso_enabled=True)
    assert get_subdomain_sso_enabled(db_session, settings_on) is True


def test_toggle_updates_without_restart(db_session: Session):
    settings = _settings(subdomain_sso_enabled=False)
    ensure_portal_settings(db_session, settings)
    assert get_subdomain_sso_enabled(db_session, settings) is False

    set_subdomain_sso_enabled(db_session, settings, True, actor="admin@test")
    assert get_subdomain_sso_enabled(db_session, settings) is True
    # Env/Settings still False — DB wins
    assert settings.subdomain_sso_enabled is False

    audit = (
        db_session.query(AuditLog)
        .filter_by(action="portal_settings.subdomain_sso_enabled")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details["previous"] is False
    assert audit.details["new"] is True


def test_resolve_target_respects_db_toggle(db_session: Session):
    settings = _settings(subdomain_sso_enabled=False)
    set_subdomain_sso_enabled(db_session, settings, True, actor="admin")
    app = App(
        slug="crm",
        label="CRM",
        upstream_url="http://10.0.0.1/",
        access_mode="subdomain_proxy",
        public_fqdn="crm.example.fr",
        enabled=True,
    )
    mode, url, fqdn = _resolve_target(app, settings, db_session)
    assert mode == "subdomain"
    assert url == "https://crm.example.fr/"
    assert fqdn == "crm.example.fr"

    set_subdomain_sso_enabled(db_session, settings, False, actor="admin")
    mode, url, fqdn = _resolve_target(app, settings, db_session)
    assert mode == "legacy"
    assert url == "/proxy/crm/"


def test_admin_toggle_requires_ack_to_enable(client: TestClient, db_session: Session):
    settings = _settings(subdomain_sso_enabled=False)
    ensure_portal_settings(db_session, settings)

    denied = client.post(
        "/admin/security/subdomain-sso",
        headers=ADMIN_HEADERS,
        data={"enabled": "on"},
        follow_redirects=False,
    )
    assert denied.status_code == 302
    assert get_subdomain_sso_enabled(db_session, settings) is False

    ok = client.post(
        "/admin/security/subdomain-sso",
        headers=ADMIN_HEADERS,
        data={"enabled": "on", "infra_ack": "on"},
        follow_redirects=False,
    )
    assert ok.status_code == 302
    assert get_subdomain_sso_enabled(db_session, settings) is True


def test_admin_security_page_shows_enabled_when_seeded(
    client: TestClient, db_session: Session
):
    """After migrate with SUBDOMAIN_SSO_ENABLED=true, UI shows Activé without extra action."""
    settings = _settings(subdomain_sso_enabled=True)
    ensure_portal_settings(db_session, settings)
    # Ensure row reflects enabled (same as migration seed from env=true)
    row = db_session.query(PortalSettings).filter_by(id=1).one()
    row.subdomain_sso_enabled = True
    db_session.commit()

    db_session.add(
        App(
            slug="transfer",
            label="Transfer",
            upstream_url="http://10.0.0.1/",
            access_mode="subdomain_proxy",
            public_fqdn="transfer.example.fr",
            enabled=True,
        )
    )
    db_session.commit()

    resp = client.get("/admin/security", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Activé" in resp.text
    assert "transfer.example.fr" in resp.text
    assert 'name="enabled"' in resp.text and "checked" in resp.text
    assert 'id="security-tabs"' in resp.text
    assert "Chiffrement au repos (SQLCipher)" in resp.text
    assert "Désactivé (fichier en clair)" in resp.text or "Chiffrement DB" in resp.text
