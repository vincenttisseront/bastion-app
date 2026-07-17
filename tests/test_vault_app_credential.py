"""Vault app credential service — encrypt/set/rotate/deactivate."""

from __future__ import annotations

import logging

import pytest
from sqlalchemy.orm import Session

from app.models import App, AppCredential, AuditLog
from app.sso_settings import Settings
from app.vault.app_credential_service import (
    CredentialNotFoundError,
    EncryptionNotConfiguredError,
    deactivate_app_credential,
    get_app_credential,
    get_decrypted_password,
    rotate_app_credential,
    set_app_credential,
)

SECRET_PASSWORD = "SuperSecretCrushPass-NeverInLogs"


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
        enabled=True,
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def test_set_get_rotate_deactivate(db_session: Session):
    _make_app(db_session)
    settings = _settings()

    cred = set_app_credential(
        db_session, "transfer", "robot", SECRET_PASSWORD, settings, actor="admin@test"
    )
    assert cred.app_slug == "transfer"
    assert cred.robotic_username == "robot"
    assert cred.is_active is True
    assert SECRET_PASSWORD not in cred.encrypted_password
    assert get_decrypted_password(db_session, "transfer", settings) == SECRET_PASSWORD

    rotated = rotate_app_credential(
        db_session, "transfer", "Rotated-Secret-Value", settings, actor="admin@test"
    )
    assert rotated.rotated_at is not None
    assert get_decrypted_password(db_session, "transfer", settings) == "Rotated-Secret-Value"

    deactivate_app_credential(db_session, "transfer", actor="admin@test")
    refreshed = get_app_credential(db_session, "transfer")
    assert refreshed is not None
    assert refreshed.is_active is False
    with pytest.raises(CredentialNotFoundError):
        get_decrypted_password(db_session, "transfer", settings)

    actions = [row.action for row in db_session.query(AuditLog).order_by(AuditLog.id).all()]
    assert actions == ["credential.set", "credential.rotate", "credential.deactivate"]


def test_encryption_not_configured_raises(db_session: Session):
    _make_app(db_session)
    settings = _settings(portal_secret_encryption_key="", vault_portal_vault_fernet_key="")
    with pytest.raises(EncryptionNotConfiguredError):
        set_app_credential(db_session, "transfer", "robot", SECRET_PASSWORD, settings)


def test_plaintext_password_never_in_logs(db_session: Session, caplog):
    _make_app(db_session)
    settings = _settings()
    with caplog.at_level(logging.DEBUG):
        set_app_credential(db_session, "transfer", "robot", SECRET_PASSWORD, settings)
        rotate_app_credential(db_session, "transfer", SECRET_PASSWORD + "-2", settings)
        get_decrypted_password(db_session, "transfer", settings)
        deactivate_app_credential(db_session, "transfer")

    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert SECRET_PASSWORD not in joined
    assert (SECRET_PASSWORD + "-2") not in joined

    for row in db_session.query(AuditLog).all():
        blob = f"{row.action}|{row.target}|{row.details}"
        assert SECRET_PASSWORD not in blob
        assert "Rotated" not in blob or SECRET_PASSWORD not in blob


def test_set_replaces_existing_credential(db_session: Session):
    _make_app(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "robot-a", "pass-a", settings)
    set_app_credential(db_session, "transfer", "robot-b", "pass-b", settings)
    assert db_session.query(AppCredential).count() == 1
    cred = get_app_credential(db_session, "transfer")
    assert cred is not None
    assert cred.robotic_username == "robot-b"
    assert get_decrypted_password(db_session, "transfer", settings) == "pass-b"
