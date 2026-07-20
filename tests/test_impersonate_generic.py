"""Impersonation tests for generic vault drivers."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.admin.throttling import reset_test_rate_limits
from app.bastion.drivers.base import DriverLoginResult, DriverLoginError
from app.models import App, AppGroup, AuditLog, RBACGroup
from app.robotic.impersonate_service import (
    ImpersonationError,
    get_basic_auth_header,
    impersonate,
)
from app.sso_settings import Settings
from app.vault.app_credential_service import set_app_credential

SECRET_PASSWORD = "ImpersonateGenericSecret-MustNotLeak"

USER_HEADERS = {
    "X-Email": "user@example.com",
    "X-Groups": "app-users",
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


def _make_generic_form_app(db: Session) -> App:
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
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def _make_basic_auth_app(db: Session) -> App:
    app = App(
        slug="grafana",
        label="Grafana",
        upstream_url="https://grafana.example/",
        robotic_driver="generic_basic_auth",
        auth_mode="generic_basic_auth",
        access_mode="legacy_path_proxy",
        enabled=True,
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def _seed_rbac(db: Session, app: App) -> None:
    group = RBACGroup(name="app-users")
    db.add(group)
    db.commit()
    db.refresh(group)
    db.add(AppGroup(app_id=app.id, group_id=group.id))
    db.commit()


@pytest.mark.asyncio
async def test_generic_form_impersonate_success(db_session: Session, caplog):
    _make_generic_form_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "wiki", "robot", SECRET_PASSWORD, settings)

    fake_result = DriverLoginResult(cookies={"sessionid": "sess-value-123"})
    with (
        patch(
            "app.robotic.impersonate_service.generic_form_login",
            new=AsyncMock(return_value=fake_result),
        ),
        caplog.at_level(logging.DEBUG),
    ):
        result = await impersonate(db_session, "wiki", settings, actor="user@test")

    assert result.cookies["sessionid"] == "sess-value-123"
    assert result.target_url == "/proxy/wiki/"
    assert result.driver == "generic_form"

    audit = (
        db_session.query(AuditLog)
        .filter_by(action="robotic.impersonate.generic")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details["success"] is True
    assert audit.details["driver"] == "generic_form"
    assert SECRET_PASSWORD not in str(audit.details)
    assert SECRET_PASSWORD not in "\n".join(r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_generic_form_impersonate_login_failure(db_session: Session):
    _make_generic_form_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "wiki", "robot", SECRET_PASSWORD, settings)

    with patch(
        "app.robotic.impersonate_service.generic_form_login",
        new=AsyncMock(side_effect=DriverLoginError("Generic form login rejected")),
    ):
        with pytest.raises(ImpersonationError, match="rejected"):
            await impersonate(db_session, "wiki", settings)


@pytest.mark.asyncio
async def test_basic_auth_header_success(db_session: Session, caplog):
    _make_basic_auth_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "grafana", "robot", SECRET_PASSWORD, settings)

    with caplog.at_level(logging.DEBUG):
        result = await get_basic_auth_header(db_session, "grafana", settings, actor="user@test")

    assert result.auth_header.startswith("Basic ")
    assert SECRET_PASSWORD not in result.auth_header
    audit = (
        db_session.query(AuditLog)
        .filter_by(action="robotic.impersonate.generic")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details["driver"] == "generic_basic_auth"
    assert SECRET_PASSWORD not in str(audit.details)
    assert SECRET_PASSWORD not in "\n".join(r.getMessage() for r in caplog.records)


def test_generic_form_impersonate_route_302(client: TestClient, db_session: Session):
    app = _make_generic_form_app(db_session)
    _seed_rbac(db_session, app)
    set_app_credential(db_session, "wiki", "robot", SECRET_PASSWORD, _settings())

    fake_result = DriverLoginResult(cookies={"sessionid": "cookie-val-xyz"})
    with patch(
        "app.robotic.impersonate_service.generic_form_login",
        new=AsyncMock(return_value=fake_result),
    ):
        resp = client.get(
            "/api/internal/impersonate/wiki",
            headers=USER_HEADERS,
            follow_redirects=False,
        )

    assert resp.status_code == 302
    assert resp.headers["location"] == "/proxy/wiki/"
    assert "sessionid" in resp.cookies or "sessionid=" in resp.headers.get("set-cookie", "")
    assert SECRET_PASSWORD not in resp.text
    assert SECRET_PASSWORD not in str(resp.headers)


def test_basic_auth_header_route_returns_header_not_body(client: TestClient, db_session: Session):
    app = _make_basic_auth_app(db_session)
    _seed_rbac(db_session, app)
    set_app_credential(db_session, "grafana", "robot", SECRET_PASSWORD, _settings())

    with patch(
        "app.robotic.impersonate_service.generic_basic_auth_header",
        return_value="Basic cm9ib3Q6c2VjcmV0",
    ):
        resp = client.get(
            "/internal/basic-auth-header/grafana",
            headers=USER_HEADERS,
        )

    assert resp.status_code == 200
    assert resp.headers.get("x-robotic-authorization", "").startswith("Basic ")
    assert resp.text == ""
    assert SECRET_PASSWORD not in resp.text
    assert SECRET_PASSWORD not in str(resp.headers)


def test_basic_auth_header_throttled(client: TestClient, db_session: Session):
    app = _make_basic_auth_app(db_session)
    _seed_rbac(db_session, app)
    set_app_credential(db_session, "grafana", "robot", SECRET_PASSWORD, _settings())

    with patch(
        "app.robotic.impersonate_service.generic_basic_auth_header",
        return_value="Basic cm9ib3Q6c2VjcmV0",
    ):
        first = client.get("/internal/basic-auth-header/grafana", headers=USER_HEADERS)
        second = client.get("/internal/basic-auth-header/grafana", headers=USER_HEADERS)

    assert first.status_code == 200
    assert second.status_code == 429
