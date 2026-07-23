"""Client open action — GET /api/internal/impersonate/{slug}."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.admin.throttling import reset_test_rate_limits
from app.bastion.drivers.crushftp import CrushFTPSession
from app.models import App, RBACGroup
from app.rbac.grants_service import AccessGrantCreate, create_grant
from app.vault.app_credential_service import set_app_credential
from app.sso_settings import Settings

USER_HEADERS = {
    "X-Email": "user@example.com",
    "X-Groups": "transfer-users",
}
ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}
DENIED_HEADERS = {
    "X-Email": "other@example.com",
    "X-Groups": "unrelated-group",
}
INTERNAL = {"Authorization": "Bearer test-secret"}

SECRET_PASSWORD = "ClientOpenSecret-MustNotAppear"


@pytest.fixture(autouse=True)
def _reset_throttle():
    reset_test_rate_limits()
    yield
    reset_test_rate_limits()


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )


def _seed_app(db: Session, *, with_group: bool = True) -> App:
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


def test_robotic_impersonate_302_with_cookies(client: TestClient, db_session: Session):
    _seed_app(db_session)
    set_app_credential(db_session, "transfer", "robot", SECRET_PASSWORD, _settings())

    fake_session = CrushFTPSession(
        cookies={"CrushAuth": "COOKIEVALUEABCD", "currentAuth": "ABCD"},
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
    ):
        resp = client.get(
            "/api/internal/impersonate/transfer",
            headers=USER_HEADERS,
            follow_redirects=False,
        )

    assert resp.status_code == 302
    assert resp.headers["location"] == "/proxy/transfer/"
    set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    if not set_cookies:
        # Starlette merges Set-Cookie; TestClient exposes via cookies / raw headers
        raw = resp.headers.get("set-cookie", "")
        set_cookies = [raw] if raw else []
        # Also check cookie jar
    assert "CrushAuth" in resp.cookies or any("CrushAuth=" in c for c in set_cookies)
    assert SECRET_PASSWORD not in resp.text
    assert SECRET_PASSWORD not in str(resp.headers)


def test_robotic_impersonate_403_without_rbac(client: TestClient, db_session: Session):
    _seed_app(db_session, with_group=True)
    set_app_credential(db_session, "transfer", "robot", SECRET_PASSWORD, _settings())
    resp = client.get(
        "/api/internal/impersonate/transfer",
        headers=DENIED_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 403


def test_robotic_impersonate_clear_error_without_credential(client: TestClient, db_session: Session):
    _seed_app(db_session)
    resp = client.get(
        "/api/internal/impersonate/transfer",
        headers=USER_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 404
    body = resp.json()
    assert body["ok"] is False
    assert "credential" in body["error"].lower()
    assert SECRET_PASSWORD not in resp.text


def test_admin_credential_api_never_returns_password(client: TestClient, db_session: Session):
    _seed_app(db_session, with_group=False)
    create = client.post(
        "/api/admin/apps/transfer/credential",
        headers=INTERNAL,
        json={"robotic_username": "robot", "password": SECRET_PASSWORD},
    )
    assert create.status_code == 200
    data = create.json()
    assert data["robotic_username"] == "robot"
    assert "password" not in data
    assert SECRET_PASSWORD not in create.text

    read = client.get("/api/admin/apps/transfer/credential", headers=INTERNAL)
    assert read.status_code == 200
    assert "password" not in read.json()
    assert SECRET_PASSWORD not in read.text
