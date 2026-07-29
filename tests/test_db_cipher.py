"""Unit tests for SQLCipher key handling (no sqlcipher3 required on Windows)."""

from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool

from app.db_cipher import (
    DbEncryptionError,
    assert_db_cipher_state,
    create_portal_engine,
    db_encryption_key_path,
    get_db_encryption_status,
    normalize_db_encryption_key,
    pragma_key_sql,
    probe_plaintext_readable,
    resolve_db_encryption_key,
    sqlite_path_from_url,
)
from app.sso_settings import Settings, get_settings


def test_normalize_db_encryption_key_accepts_hex64():
    key = "a" * 64
    assert normalize_db_encryption_key(key) == key
    assert normalize_db_encryption_key(f"x'{key}'") == key
    assert normalize_db_encryption_key(key.upper()) == key


def test_normalize_db_encryption_key_rejects_bad():
    with pytest.raises(DbEncryptionError):
        normalize_db_encryption_key("too-short")
    with pytest.raises(DbEncryptionError):
        normalize_db_encryption_key("g" * 64)


def test_pragma_key_sql_raw_hex():
    key = "ab" * 32
    assert pragma_key_sql(key) == f"PRAGMA key = \"x'{key}'\""


def test_sqlite_path_from_url():
    assert sqlite_path_from_url("sqlite:////var/lib/sso-portal/portal.db") == Path(
        "/var/lib/sso-portal/portal.db"
    )
    assert sqlite_path_from_url("sqlite:///./portal.db") == Path("./portal.db")


def test_resolve_key_from_file(tmp_path, monkeypatch):
    keys = tmp_path / "keys"
    keys.mkdir()
    key = "cd" * 32
    (keys / "db_encryption.key").write_text(key + "\n", encoding="ascii")
    monkeypatch.setenv("VAULT_KEYS_DIR", str(keys))
    monkeypatch.delenv("VAULT_PORTAL_DB_ENCRYPTION_KEY", raising=False)
    get_settings.cache_clear()
    settings = Settings()
    assert resolve_db_encryption_key(settings) == key


def test_resolve_key_migrates_env_to_file(tmp_path, monkeypatch):
    keys = tmp_path / "keys"
    key = "ef" * 32
    monkeypatch.setenv("VAULT_KEYS_DIR", str(keys))
    monkeypatch.setenv("VAULT_PORTAL_DB_ENCRYPTION_KEY", key)
    get_settings.cache_clear()
    settings = Settings()
    assert resolve_db_encryption_key(settings) == key
    assert db_encryption_key_path(settings).read_text(encoding="ascii").strip() == key


def test_resolve_key_none_without_config(tmp_path, monkeypatch):
    keys = tmp_path / "keys"
    keys.mkdir()
    monkeypatch.setenv("VAULT_KEYS_DIR", str(keys))
    monkeypatch.delenv("VAULT_PORTAL_DB_ENCRYPTION_KEY", raising=False)
    get_settings.cache_clear()
    assert resolve_db_encryption_key(Settings()) is None


def test_assert_plaintext_with_key_raises(tmp_path, monkeypatch):
    import sqlite3

    db_path = tmp_path / "portal.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE t (id INTEGER)")
    conn.commit()
    conn.close()
    assert probe_plaintext_readable(db_path) is True

    with pytest.raises(DbEncryptionError, match="still plaintext"):
        assert_db_cipher_state(f"sqlite:///{db_path.as_posix()}", "ab" * 32)


def test_assert_encrypted_without_key_raises(tmp_path):
    # Non-sqlite garbage → not plaintext-readable
    db_path = tmp_path / "portal.db"
    db_path.write_bytes(b"not-a-sqlite-database" * 8)
    assert probe_plaintext_readable(db_path) is False
    with pytest.raises(DbEncryptionError, match="not readable as plaintext"):
        assert_db_cipher_state(f"sqlite:///{db_path.as_posix()}", None)


def test_create_portal_engine_sqlite_uses_null_pool(tmp_path, monkeypatch):
    """File sqlite must not use QueuePool (auth_request concurrency)."""
    from sqlalchemy.pool import NullPool

    monkeypatch.setenv("VAULT_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.delenv("VAULT_PORTAL_DB_ENCRYPTION_KEY", raising=False)
    get_settings.cache_clear()
    settings = Settings(vault_portal_db_encryption_key="")
    db_path = tmp_path / "portal.db"
    engine = create_portal_engine(f"sqlite:///{db_path.as_posix()}", settings)
    assert isinstance(engine.pool, NullPool)


def test_create_portal_engine_plaintext_memory(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.delenv("VAULT_PORTAL_DB_ENCRYPTION_KEY", raising=False)
    get_settings.cache_clear()
    settings = Settings(vault_portal_db_encryption_key="")
    engine = create_portal_engine(
        "sqlite://",
        settings,
        poolclass=StaticPool,
    )
    with engine.connect() as conn:
        from sqlalchemy import text

        assert conn.execute(text("SELECT 1")).scalar() == 1
        assert isinstance(engine.pool, StaticPool)


def test_get_db_encryption_status_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.delenv("VAULT_PORTAL_DB_ENCRYPTION_KEY", raising=False)
    get_settings.cache_clear()
    settings = Settings(database_url="sqlite://", vault_portal_db_encryption_key="")
    status = get_db_encryption_status(settings)
    assert status.enabled is False
    assert status.status_badge == "muted"
    assert "clair" in status.status_label.lower() or "Désactivé" in status.status_label


def test_get_db_encryption_status_env_ready(tmp_path, monkeypatch):
    keys = tmp_path / "keys"
    keys.mkdir()
    monkeypatch.setenv("VAULT_KEYS_DIR", str(keys))
    monkeypatch.setenv("VAULT_PORTAL_DB_ENCRYPTION_KEY", "ab" * 32)
    get_settings.cache_clear()
    settings = Settings(
        database_url="sqlite://",
        vault_portal_db_encryption_key="ab" * 32,
        vault_keys_dir=str(keys),
    )
    status = get_db_encryption_status(settings)
    assert status.enabled is True
    assert status.source == "env"
    assert status.status_badge in ("ok", "error")  # error if no sqlcipher on Windows
    assert status.status_label in ("Prêt", "Driver SQLCipher manquant")


@pytest.mark.skipif(
    __import__("importlib.util").util.find_spec("sqlcipher3") is None,
    reason="sqlcipher3 not installed (Linux wheels only)",
)
def test_encrypt_portal_db_roundtrip(tmp_path, monkeypatch):
    import sqlite3

    from scripts.encrypt_portal_db import encrypt_database

    db_path = tmp_path / "portal.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE apps (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO apps (name) VALUES ('crush')")
    conn.commit()
    conn.close()

    key = "12" * 32
    keys = tmp_path / "keys"
    keys.mkdir()
    monkeypatch.setenv("VAULT_KEYS_DIR", str(keys))
    monkeypatch.setenv("VAULT_PORTAL_DB_ENCRYPTION_KEY", key)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    get_settings.cache_clear()

    assert encrypt_database(db_path, key) == 0
    assert probe_plaintext_readable(db_path) is False
    # Idempotent
    assert encrypt_database(db_path, key) == 0

    settings = Settings()
    engine = create_portal_engine(f"sqlite:///{db_path.as_posix()}", settings)
    with engine.connect() as conn:
        from sqlalchemy import text

        name = conn.execute(text("SELECT name FROM apps")).scalar()
        assert name == "crush"
