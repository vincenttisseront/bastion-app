"""Application-managed Fernet key store — ensure / migrate / rotate / export."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy.orm import Session

from app.models import App, AppCredential, AuditLog, EncryptionKeyVersion
from app.secret_crypto import decrypt_with_key, encrypt_with_key
from app.sso_settings import Settings
from app.vault.encryption_key_store import (
    EncryptionKeyStoreError,
    ensure_encryption_key,
    export_active_key_backup,
    get_active_key,
    get_active_version,
    key_path,
    reset_active_cache_for_tests,
    resolve_keys_dir,
)
from app.vault.key_rotation_service import KeyRotationError, rotate_application_key


def _settings(tmp_path: Path, **kwargs) -> Settings:
    defaults = {
        "vault_portal_internal_token": "test-secret",
        "portal_secret_encryption_key": "",
        "vault_portal_vault_fernet_key": "",
        "database_url": "sqlite://",
        "portal_data_dir": str(tmp_path / "data"),
        "vault_keys_dir": str(tmp_path / "keys"),
    }
    defaults.update(kwargs)
    return Settings(**defaults)


@pytest.fixture(autouse=True)
def _clear_key_cache():
    reset_active_cache_for_tests()
    yield
    reset_active_cache_for_tests()


def test_ensure_generates_initial_key(db_session: Session, tmp_path: Path):
    settings = _settings(tmp_path)
    version = ensure_encryption_key(db_session, settings)
    assert version == 1
    assert get_active_version() == 1
    assert key_path(resolve_keys_dir(settings), 1).is_file()
    material = get_active_key()
    assert material
    # second boot loads same key
    reset_active_cache_for_tests()
    ensure_encryption_key(db_session, settings)
    assert get_active_key() == material
    actions = [r.action for r in db_session.query(AuditLog).all()]
    assert "key_generated_initial" in actions


def test_ensure_migrates_from_env(db_session: Session, tmp_path: Path):
    env_key = Fernet.generate_key().decode()
    settings = _settings(tmp_path, portal_secret_encryption_key=env_key)
    version = ensure_encryption_key(db_session, settings)
    assert version == 1
    assert get_active_key() == env_key
    assert key_path(resolve_keys_dir(settings), 1).read_text(encoding="ascii").strip() == env_key
    actions = [r.action for r in db_session.query(AuditLog).all()]
    assert "key_migrated_from_env" in actions
    row = db_session.query(EncryptionKeyVersion).filter_by(version=1).one()
    assert row.source == "migrated_from_env"


def test_ensure_loads_existing_without_regen(db_session: Session, tmp_path: Path):
    settings = _settings(tmp_path)
    ensure_encryption_key(db_session, settings)
    first = get_active_key()
    reset_active_cache_for_tests()
    # clear env so it cannot regenerate from env
    settings2 = _settings(tmp_path)
    ensure_encryption_key(db_session, settings2)
    assert get_active_key() == first
    assert db_session.query(EncryptionKeyVersion).count() == 1


def test_rotate_application_key_success(db_session: Session, tmp_path: Path):
    settings = _settings(tmp_path)
    ensure_encryption_key(db_session, settings)
    old = get_active_key()
    old_v = get_active_version()

    app = App(
        slug="transfer",
        label="Transfer",
        upstream_url="https://crush.example/",
        robotic_driver="crushftp",
        enabled=True,
    )
    db_session.add(app)
    db_session.commit()
    plain = "secret-never-logged"
    db_session.add(
        AppCredential(
            app_slug="transfer",
            robotic_username="robot",
            encrypted_password=encrypt_with_key(plain, old),
            is_active=True,
        )
    )
    db_session.commit()

    report = rotate_application_key(db_session, settings, actor="admin@test")
    assert report.success
    assert get_active_version() == old_v + 1
    new = get_active_key()
    assert new != old
    cred = db_session.query(AppCredential).one()
    assert decrypt_with_key(cred.encrypted_password, new) == plain
    with pytest.raises(ValueError):
        decrypt_with_key(cred.encrypted_password, old)
    assert key_path(resolve_keys_dir(settings), old_v).is_file()  # retired kept
    assert key_path(resolve_keys_dir(settings), old_v + 1).is_file()


def test_rotate_application_key_failure_cleans_orphan(db_session: Session, tmp_path: Path):
    settings = _settings(tmp_path)
    ensure_encryption_key(db_session, settings)
    old_v = get_active_version()

    app = App(
        slug="transfer",
        label="Transfer",
        upstream_url="https://crush.example/",
        robotic_driver="crushftp",
        enabled=True,
    )
    db_session.add(app)
    db_session.commit()
    db_session.add(
        AppCredential(
            app_slug="transfer",
            robotic_username="robot",
            encrypted_password="not-valid-fernet",
            is_active=True,
        )
    )
    db_session.commit()

    with pytest.raises(KeyRotationError):
        rotate_application_key(db_session, settings)

    assert get_active_version() == old_v
    assert not key_path(resolve_keys_dir(settings), old_v + 1).exists()


def test_export_backup_requires_passphrase(db_session: Session, tmp_path: Path):
    settings = _settings(tmp_path)
    ensure_encryption_key(db_session, settings)
    with pytest.raises(EncryptionKeyStoreError, match="12"):
        export_active_key_backup(settings, "short")
    blob = export_active_key_backup(settings, "long-enough-passphrase")
    assert blob.startswith(b"bastion-fernet-backup-v1\n")
    assert get_active_key().encode() not in blob
