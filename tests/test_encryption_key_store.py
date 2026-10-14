"""Application-managed Fernet key store — ensure / migrate / rotate / export."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy.orm import Session

from app.models import App, AppCredential, AuditLog, EncryptionKeyVersion
from app.secret_crypto import (
    decrypt_secret,
    decrypt_with_key,
    encrypt_with_key,
    fernet_from_key_material,
)
from app.sso_settings import Settings
from app.vault.encryption_key_store import (
    EncryptionKeyStoreError,
    derive_legacy_fernet_key,
    ensure_encryption_key,
    export_active_key_backup,
    get_active_key,
    get_active_version,
    key_path,
    reset_active_cache_for_tests,
    resolve_keys_dir,
)
from app.vault.key_rotation_service import KeyRotationError, rotate_application_key
from app.vault.keyfile import write_secret_file


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


LEGACY_PASSPHRASE = "test-encryption-key-for-pytest-only"


def test_env_passphrase_is_stored_as_its_derived_fernet_key(db_session: Session, tmp_path: Path):
    """Ciphertexts written from the passphrase must still decrypt with the stored key."""
    legacy_ciphertext = encrypt_with_key("secret", LEGACY_PASSPHRASE)
    settings = _settings(tmp_path, portal_secret_encryption_key=LEGACY_PASSPHRASE)

    ensure_encryption_key(db_session, settings)

    stored = key_path(resolve_keys_dir(settings), 1).read_text(encoding="ascii").strip()
    assert stored == get_active_key() == derive_legacy_fernet_key(LEGACY_PASSPHRASE)
    assert decrypt_secret(legacy_ciphertext, settings) == "secret"


def test_passphrase_left_in_a_key_file_is_normalized_on_boot(db_session: Session, tmp_path: Path):
    settings = _settings(tmp_path)
    keys_dir = resolve_keys_dir(settings)
    keys_dir.mkdir(parents=True)
    key_path(keys_dir, 1).write_text(LEGACY_PASSPHRASE + "\n", encoding="ascii")
    (keys_dir / "current").write_text("1\n", encoding="ascii")

    ensure_encryption_key(db_session, settings)

    assert key_path(keys_dir, 1).read_text(encoding="ascii").strip() == derive_legacy_fernet_key(
        LEGACY_PASSPHRASE
    )


def test_malformed_active_key_is_rejected_instead_of_silently_derived():
    with pytest.raises(ValueError, match="Fernet invalide"):
        fernet_from_key_material("not-a-fernet-key")


def test_write_secret_file_replaces_content_without_leftovers(tmp_path: Path):
    folder = tmp_path / "secrets"
    folder.mkdir()
    target = folder / "k.key"
    write_secret_file(target, "first")
    write_secret_file(target, "second")
    assert target.read_text(encoding="ascii") == "second\n"
    assert [p.name for p in folder.iterdir()] == ["k.key"]
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
