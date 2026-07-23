"""Robotic _check_app_rbac after AppGroup → AccessGrant bascule."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.admin.throttling import reset_test_rate_limits
from app.bastion.drivers.crushftp import CrushFTPSession
from app.models import App, RBACGroup
from app.rbac.grants_service import AccessGrantCreate, create_grant
from app.sso_settings import Settings
from app.vault.app_credential_service import set_app_credential

USER_HEADERS = {
    "X-Email": "user@example.com",
    "X-Groups": "transfer-users",
}
DENIED_HEADERS = {
    "X-Email": "other@example.com",
    "X-Groups": "unrelated-group",
}
SECRET_PASSWORD = "CheckAppRbacSecret-MustNotAppear"


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        subdomain_sso_enabled=False,
    )


def _seed_app(db: Session, *, with_grant: bool = True) -> App:
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
    if with_grant:
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
    set_app_credential(db, "transfer", "robot", SECRET_PASSWORD, _settings())
    return app


def test_check_app_rbac_allows_with_launch_grant(client: TestClient, db_session: Session):
    reset_test_rate_limits()
    _seed_app(db_session, with_grant=True)
    fake = CrushFTPSession(
        cookies={"CrushAuth": "COOKIEVALUEABCD", "currentAuth": "ABCD"},
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


def test_check_app_rbac_denies_without_grant(client: TestClient, db_session: Session):
    reset_test_rate_limits()
    _seed_app(db_session, with_grant=True)

    resp = client.get(
        "/api/internal/impersonate/transfer",
        headers=DENIED_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 403
