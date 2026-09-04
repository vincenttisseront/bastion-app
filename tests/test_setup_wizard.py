"""Tests for DB-backed setup wizard / site identity."""

from __future__ import annotations

import pytest

from app.models import PortalSettings
from app.setup_wizard_service import (
    get_effective_portal_domain,
    get_setup_status,
    mark_setup_wizard_complete,
    update_site_identity,
    write_site_env_export,
)


def test_update_site_identity_persists_and_writes_export(db_session, tmp_path, monkeypatch):
    from app.sso_settings import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "exports_dir", str(tmp_path))
    monkeypatch.setattr(settings, "portal_domain", "portal.example.com")

    update_site_identity(
        db_session,
        settings,
        portal_domain="portal.customer.tld",
        default_realm_slug="corp",
        actor="admin@test",
    )
    row = db_session.query(PortalSettings).filter_by(id=1).one()
    assert row.portal_domain == "portal.customer.tld"
    assert row.default_realm_slug == "corp"
    assert get_effective_portal_domain(db_session, settings) == "portal.customer.tld"
    env_path = tmp_path / "bastion-site.env"
    assert env_path.is_file()
    text = env_path.read_text(encoding="utf-8")
    assert "PORTAL_DOMAIN=portal.customer.tld" in text
    assert "SSO_PORTAL_DEFAULT_REALM_SLUG=corp" in text


def test_rejects_placeholder_domain(db_session, tmp_path, monkeypatch):
    from app.sso_settings import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "exports_dir", str(tmp_path))
    with pytest.raises(ValueError):
        update_site_identity(
            db_session,
            settings,
            portal_domain="portal.example.com",
            default_realm_slug="default",
            actor="admin",
        )


def test_setup_status_needs_wizard_when_placeholder(db_session, monkeypatch):
    from app.sso_settings import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "portal_domain", "portal.example.com")
    status = get_setup_status(db_session, settings)
    # No breakglass yet → needs_wizard false (cannot access admin wizard)
    assert status.needs_wizard is False


def test_write_site_env_export(tmp_path, monkeypatch):
    from app.sso_settings import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "exports_dir", str(tmp_path))
    path = write_site_env_export(
        settings, portal_domain="a.example.org", default_realm_slug="default"
    )
    assert path.name == "bastion-site.env"
    assert "PORTAL_DOMAIN=a.example.org" in path.read_text(encoding="utf-8")


def test_complete_requires_domain_and_realm(db_session, monkeypatch):
    from app.sso_settings import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "portal_domain", "portal.example.com")
    with pytest.raises(ValueError):
        mark_setup_wizard_complete(db_session, settings, actor="admin")
