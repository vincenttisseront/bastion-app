"""User app credential service — override resolution and CRUD."""

from __future__ import annotations

import logging

import pytest
from sqlalchemy.orm import Session

from app.models import App, AuditLog
from app.sso_settings import Settings
from app.vault.app_credential_service import set_app_credential
from app.vault.user_app_credential_service import (
    delete_user_credential,
    get_effective_credential,
    has_user_override,
    resolve_credential,
    set_user_credential,
)

SECRET_SHARED = "SharedVaultSecret-MustNotLeak"
SECRET_USER = "UserOverrideSecret-MustNotLeak"
KC_USER = "e189ed16-79f0-4fa1-85ee-1bb7ff28052c"


def _settings(**kwargs) -> Settings:
    defaults = {
        "vault_portal_internal_token": "test-secret",
        "portal_secret_encryption_key": "test-encryption-key-for-pytest-only",
        "database_url": "sqlite://",
    }
    defaults.update(kwargs)
    return Settings(**defaults)


def _make_app(db: Session, slug: str = "transfer") -> App:
    app = App(
        slug=slug,
        label="Transfer",
        upstream_url="https://crush.example/",
        robotic_driver="crushftp",
        access_mode="legacy_path_proxy",
        enabled=True,
    )
    db.add(app)
    db.commit()
    return app


def test_effective_falls_back_to_shared(db_session: Session):
    _make_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "shared-robot", SECRET_SHARED, settings)

    row, source = get_effective_credential(db_session, "transfer", KC_USER)
    assert source == "shared"
    assert row is not None
    assert row.robotic_username == "shared-robot"
    assert has_user_override(db_session, "transfer", KC_USER) is False

    resolved, password = resolve_credential(db_session, "transfer", settings, KC_USER)
    assert resolved.source == "shared"
    assert password == SECRET_SHARED
    assert SECRET_USER not in password


def test_effective_prefers_user_override(db_session: Session, caplog):
    _make_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "shared-robot", SECRET_SHARED, settings)
    set_user_credential(
        db_session, "transfer", KC_USER, "user-robot", SECRET_USER, settings, actor="admin@test"
    )

    assert has_user_override(db_session, "transfer", KC_USER) is True
    row, source = get_effective_credential(db_session, "transfer", KC_USER)
    assert source == "user_override"
    assert row is not None
    assert row.robotic_username == "user-robot"

    resolved, password = resolve_credential(db_session, "transfer", settings, KC_USER)
    assert resolved.source == "user_override"
    assert password == SECRET_USER

    with caplog.at_level(logging.DEBUG):
        pass
    audit = (
        db_session.query(AuditLog)
        .filter_by(action="credential.user.set")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert SECRET_USER not in str(audit.details)
    assert SECRET_SHARED not in str(audit.details)


def test_delete_override_returns_to_shared(db_session: Session):
    _make_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "shared-robot", SECRET_SHARED, settings)
    set_user_credential(
        db_session, "transfer", KC_USER, "user-robot", SECRET_USER, settings
    )
    assert delete_user_credential(db_session, "transfer", KC_USER, actor="admin") is True
    assert has_user_override(db_session, "transfer", KC_USER) is False

    resolved, password = resolve_credential(db_session, "transfer", settings, KC_USER)
    assert resolved.source == "shared"
    assert resolved.robotic_username == "shared-robot"
    assert password == SECRET_SHARED


def test_no_credential_returns_none(db_session: Session):
    _make_app(db_session)
    row, source = get_effective_credential(db_session, "transfer", KC_USER)
    assert row is None
    assert source is None
