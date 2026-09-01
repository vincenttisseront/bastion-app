"""app_launch_url — robotic drivers vs direct access modes."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.access_modes import app_launch_url
from app.admin.throttling import reset_test_rate_limits
from app.bastion.drivers.base import DriverLoginResult
from app.bastion.drivers.crushftp import CrushFTPSession
from app.models import App, RBACGroup
from app.robotic.impersonate_service import _resolve_target
from app.sso_settings import Settings
from app.vault.app_credential_service import set_app_credential
from app.rbac.grants_service import AccessGrantCreate, create_grant

SECRET = "LaunchUrlSecret-MustNotLeak"

USER_HEADERS = {
    "X-Email": "user@example.com",
    "X-Groups": "transfer-users",
}


def _app(**kwargs) -> SimpleNamespace:
    defaults = {
        "slug": "demo",
        "access_mode": "legacy_path_proxy",
        "upstream_url": "https://upstream.example/",
        "public_fqdn": None,
        "robotic_driver": None,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_launch_url_crushftp_uses_impersonate():
    app = _app(slug="transfer", robotic_driver="crushftp")
    assert app_launch_url(app) == "/api/internal/impersonate/transfer"


def test_launch_url_generic_form_uses_impersonate():
    app = _app(slug="wiki", robotic_driver="generic_form", access_mode="sso_gate")
    assert app_launch_url(app) == "/api/internal/impersonate/wiki"


def test_launch_url_teleport_uses_impersonate():
    app = _app(
        slug="teleport",
        robotic_driver="teleport",
        access_mode="subdomain_proxy",
        public_fqdn="teleport.ar-systems.fr",
    )
    assert app_launch_url(app) == "/api/internal/impersonate/teleport"


def test_launch_url_generic_basic_auth_stays_direct():
    app = _app(
        slug="grafana",
        robotic_driver="generic_basic_auth",
        access_mode="legacy_path_proxy",
    )
    assert app_launch_url(app) == "/proxy/grafana/"

    sub = _app(
        slug="grafana",
        robotic_driver="generic_basic_auth",
        access_mode="subdomain_proxy",
        public_fqdn="grafana.example.fr",
    )
    assert app_launch_url(sub) == "https://grafana.example.fr"


def test_launch_url_generic_wsse_stays_direct():
    app = _app(
        slug="ovh-api",
        robotic_driver="generic_wsse",
        access_mode="legacy_path_proxy",
    )
    assert app_launch_url(app) == "/proxy/ovh-api/"

    sub = _app(
        slug="ovh-api",
        robotic_driver="generic_wsse",
        access_mode="subdomain_proxy",
        public_fqdn="api.example.fr",
    )
    assert app_launch_url(sub) == "https://api.example.fr"


def test_launch_url_sso_without_driver_unchanged():
    app = _app(
        slug="wiki",
        robotic_driver=None,
        access_mode="sso_gate",
        upstream_url="https://wiki.example.fr/",
    )
    assert app_launch_url(app) == "https://wiki.example.fr/"

    legacy = _app(slug="legacy-app", robotic_driver=None, access_mode="legacy_path_proxy")
    assert app_launch_url(legacy) == "/proxy/legacy-app/"

    sub = _app(
        slug="sub",
        robotic_driver=None,
        access_mode="subdomain_proxy",
        public_fqdn="sub.example.fr",
    )
    assert app_launch_url(sub) == "https://sub.example.fr"


def test_resolve_target_legacy_and_subdomain(db_session: Session):
    settings_off = Settings(
        vault_portal_internal_token="t",
        portal_secret_encryption_key="k",
        database_url="sqlite://",
        subdomain_sso_enabled=False,
    )
    legacy = App(
        slug="transfer",
        label="T",
        upstream_url="https://crush.example/",
        access_mode="legacy_path_proxy",
        robotic_driver="crushftp",
        enabled=True,
    )
    mode, url, fqdn = _resolve_target(legacy, settings_off, db_session)
    assert mode == "legacy"
    assert url == "/proxy/transfer/"
    assert fqdn is None

    settings_on = Settings(
        vault_portal_internal_token="t",
        portal_secret_encryption_key="k",
        database_url="sqlite://",
        subdomain_sso_enabled=True,
    )
    sub = App(
        slug="transfer",
        label="T",
        upstream_url="http://10.0.0.1/",
        access_mode="subdomain_proxy",
        public_fqdn="transfer.example.fr",
        robotic_driver="crushftp",
        enabled=True,
    )
    # No portal_settings row → fallback on Settings.subdomain_sso_enabled
    mode, url, fqdn = _resolve_target(sub, settings_on, db_session)
    assert mode == "subdomain"
    assert url == "https://transfer.example.fr/WebInterface/new-ui/index.html"
    assert fqdn == "transfer.example.fr"
    assert url != "/"


def test_crushftp_resolve_target_ignores_login_html_form_url(db_session: Session):
    """login_form_url often points at login.html — post-SSO must land on new-ui."""
    settings_on = Settings(
        vault_portal_internal_token="t",
        portal_secret_encryption_key="k",
        database_url="sqlite://",
        subdomain_sso_enabled=True,
    )
    sub = App(
        slug="transfer",
        label="T",
        upstream_url="http://10.0.0.1/",
        access_mode="subdomain_proxy",
        public_fqdn="transfer.example.fr",
        robotic_driver="crushftp",
        login_form_url="https://transfer.example.fr/WebInterface/login.html",
        enabled=True,
    )
    mode, url, fqdn = _resolve_target(sub, settings_on, db_session)
    assert mode == "subdomain"
    assert url == "https://transfer.example.fr/WebInterface/new-ui/index.html"
    assert "login.html" not in url
    assert fqdn == "transfer.example.fr"


@pytest.fixture(autouse=True)
def _reset_throttle():
    reset_test_rate_limits()
    yield
    reset_test_rate_limits()


def _seed_crush(db: Session, *, access_mode: str = "legacy_path_proxy", fqdn: str | None = None) -> App:
    app = App(
        slug="transfer",
        label="Transfer",
        upstream_url="https://crush.example/",
        robotic_driver="crushftp",
        access_mode=access_mode,
        public_fqdn=fqdn,
        enabled=True,
    )
    db.add(app)
    db.commit()
    db.refresh(app)
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


def test_impersonate_302_to_proxy_not_portal_root(client: TestClient, db_session: Session):
    _seed_crush(db_session)
    set_app_credential(
        db_session,
        "transfer",
        "robot",
        SECRET,
        Settings(
            vault_portal_internal_token="test-secret",
            portal_secret_encryption_key="test-encryption-key-for-pytest-only",
            database_url="sqlite://",
        ),
    )
    fake = CrushFTPSession(
        cookies={"CrushAuth": "ABCDEFGH1234", "currentAuth": "1234"},
        base_url="https://crush.example/",
    )
    with (
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.login",
            new=AsyncMock(return_value=fake),
        ),
        patch(
            "app.robotic.impersonate_service.CrushFTPDriver.get_username",
            new=AsyncMock(return_value="robot"),
        ),
    ):
        resp = client.get(
            "/api/internal/impersonate/transfer",
            headers=USER_HEADERS,
            follow_redirects=False,
        )

    assert resp.status_code == 302
    assert resp.headers["location"] == "/proxy/transfer/"
    assert resp.headers["location"] != "/"
    assert resp.headers["location"] != "/apps"


def test_impersonate_generic_form_302_to_proxy(client: TestClient, db_session: Session):
    app = App(
        slug="wiki",
        label="Wiki",
        upstream_url="https://wiki.example/",
        robotic_driver="generic_form",
        auth_mode="generic_form",
        access_mode="legacy_path_proxy",
        login_form_url="https://wiki.example/login",
        enabled=True,
    )
    db_session.add(app)
    db_session.commit()
    db_session.refresh(app)
    group = RBACGroup(name="transfer-users")
    db_session.add(group)
    db_session.commit()
    db_session.refresh(group)
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        granted_by="test",
    )
    db_session.commit()
    set_app_credential(
        db_session,
        "wiki",
        "robot",
        SECRET,
        Settings(
            vault_portal_internal_token="test-secret",
            portal_secret_encryption_key="test-encryption-key-for-pytest-only",
            database_url="sqlite://",
        ),
    )

    with patch(
        "app.robotic.impersonate_service.generic_form_login",
        new=AsyncMock(return_value=DriverLoginResult(cookies={"sessionid": "abc"})),
    ):
        resp = client.get(
            "/api/internal/impersonate/wiki",
            headers=USER_HEADERS,
            follow_redirects=False,
        )

    assert resp.status_code == 302
    assert resp.headers["location"] == "/proxy/wiki/"
