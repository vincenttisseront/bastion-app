"""SQLCipher at-rest encryption for portal.db (file-level, independent of Fernet).

Key resolution (before any DB open — no DB metadata):
  1. File {keys_dir}/db_encryption.key (hex, 64 chars = 32 bytes)
  2. Env VAULT_PORTAL_DB_ENCRYPTION_KEY → migrate to file
  3. None → plaintext mode (tests / local without key)

PRAGMA key is applied via SQLAlchemy connect event — never in the URL.
"""

from __future__ import annotations

import logging
import os
import re
import stat
from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine

from app.sso_settings import Settings
from app.vault.encryption_key_store import resolve_keys_dir

logger = logging.getLogger(__name__)

DB_ENCRYPTION_KEY_FILENAME = "db_encryption.key"
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


class DbEncryptionError(RuntimeError):
    """Fatal SQLCipher / DB encryption configuration error."""


def _import_sqlcipher():
    try:
        import sqlcipher3

        return sqlcipher3
    except ImportError as exc:
        raise DbEncryptionError(
            "sqlcipher3 is required when VAULT_PORTAL_DB_ENCRYPTION_KEY / "
            f"{DB_ENCRYPTION_KEY_FILENAME} is configured. "
            "Install sqlcipher3-binary (Linux wheels) or build sqlcipher3."
        ) from exc


def normalize_db_encryption_key(raw: str) -> str:
    """Return lowercase 64-char hex key, or raise DbEncryptionError."""
    material = (raw or "").strip()
    if material.startswith(("x'", "X'")) and material.endswith("'"):
        material = material[2:-1]
    if material.lower().startswith("x'") and material.endswith("'"):
        material = material[2:-1]
    material = material.replace(" ", "").replace("\n", "")
    if not _HEX64.fullmatch(material):
        raise DbEncryptionError(
            "DB encryption key must be 64 hex characters (32 bytes). "
            "Generate with: openssl rand -hex 32"
        )
    return material.lower()


def db_encryption_key_path(settings: Settings) -> Path:
    return resolve_keys_dir(settings) / DB_ENCRYPTION_KEY_FILENAME


def _ensure_keys_dir_perms(keys_dir: Path) -> None:
    try:
        keys_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DbEncryptionError(f"cannot create keys directory: {keys_dir}") from exc
    try:
        os.chmod(keys_dir, stat.S_IRWXU)  # 0700
    except OSError:
        pass


def _write_key_file(path: Path, key_hex: str) -> None:
    path.write_text(key_hex + "\n", encoding="ascii")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError as exc:
        raise DbEncryptionError(f"cannot set permissions on {path}") from exc


def resolve_db_encryption_key(settings: Settings) -> str | None:
    """
    Resolve SQLCipher raw key (hex). Returns None for plaintext mode.
    When env bootstrap succeeds, persists to keys_dir for rotation readiness.
    """
    path = db_encryption_key_path(settings)
    if path.is_file():
        raw = path.read_text(encoding="ascii").strip()
        if not raw:
            raise DbEncryptionError(f"empty DB encryption key file: {path}")
        return normalize_db_encryption_key(raw)

    env_raw = (settings.vault_portal_db_encryption_key or "").strip()
    if not env_raw:
        return None

    key_hex = normalize_db_encryption_key(env_raw)
    keys_dir = resolve_keys_dir(settings)
    _ensure_keys_dir_perms(keys_dir)
    _write_key_file(path, key_hex)
    logger.info("DB encryption key migrated from env to %s", path)
    return key_hex


def pragma_key_sql(key_hex: str) -> str:
    normalized = normalize_db_encryption_key(key_hex)
    # Raw key form — skips SQLCipher passphrase KDF.
    return f"PRAGMA key = \"x'{normalized}'\""


def apply_pragma_key(dbapi_connection, key_hex: str) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute(pragma_key_sql(key_hex))
    finally:
        cursor.close()


def verify_db_readable(connection) -> None:
    """
    Fail-fast if the key is wrong / missing for an encrypted file.
    SQLCipher may not error on PRAGMA key alone — probe sqlite_master.
    """
    try:
        connection.execute(text("SELECT count(*) FROM sqlite_master")).scalar()
    except Exception as exc:
        raise DbEncryptionError(
            "portal.db is not readable with the configured SQLCipher key "
            "(wrong key, corrupted file, or plaintext DB opened with a key). "
            "Check VAULT_PORTAL_DB_ENCRYPTION_KEY / keys/db_encryption.key."
        ) from exc


def _register_key_on_connect(engine: Engine, key_hex: str) -> None:
    @event.listens_for(engine, "connect")
    def _set_sqlcipher_key(dbapi_connection, _connection_record) -> None:  # noqa: ANN001
        apply_pragma_key(dbapi_connection, key_hex)


def create_portal_engine(database_url: str, settings: Settings | None = None, **kwargs) -> Engine:
    """
    Create SQLAlchemy engine; inject SQLCipher key when configured.
    Extra kwargs are forwarded to create_engine (e.g. poolclass for tests).
    """
    from app.sso_settings import get_settings

    cfg = settings or get_settings()
    key_hex = resolve_db_encryption_key(cfg)
    connect_args = dict(kwargs.pop("connect_args", {}) or {})
    connect_args.setdefault("check_same_thread", False)

    engine_kwargs: dict = {
        "connect_args": connect_args,
        **kwargs,
    }

    assert_db_cipher_state(database_url, key_hex)

    if key_hex is not None:
        sqlcipher3 = _import_sqlcipher()
        engine_kwargs["module"] = sqlcipher3
        engine = create_engine(database_url, **engine_kwargs)
        _register_key_on_connect(engine, key_hex)
        with engine.connect() as conn:
            verify_db_readable(conn)
        logger.info("SQLCipher enabled for portal database")
        return engine

    return create_engine(database_url, **engine_kwargs)


def sqlite_path_from_url(database_url: str) -> Path:
    if not database_url.startswith("sqlite"):
        raise DbEncryptionError(f"Only sqlite DATABASE_URL supported, got: {database_url}")
    if ":memory:" in database_url or database_url.rstrip("/") in ("sqlite:", "sqlite://"):
        raise DbEncryptionError("in-memory sqlite URL has no filesystem path")
    return Path(database_url.split("///", 1)[-1])


def is_memory_database_url(database_url: str) -> bool:
    return ":memory:" in database_url or database_url.rstrip("/") in ("sqlite:", "sqlite://")


def probe_plaintext_readable(db_path: Path) -> bool:
    """True if the file opens as a normal SQLite DB without a SQLCipher key."""
    import sqlite3

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return True
    except Exception:
        return False
    finally:
        conn.close()


def assert_db_cipher_state(database_url: str, key_hex: str | None) -> None:
    """
    Guard against mismatch: encrypted file without key, or plaintext file with key.
    Skip for in-memory / missing / empty files (greenfield).
    """
    if is_memory_database_url(database_url):
        return
    db_path = sqlite_path_from_url(database_url)
    if not db_path.is_file() or db_path.stat().st_size == 0:
        return

    plaintext = probe_plaintext_readable(db_path)
    if key_hex is None:
        if not plaintext:
            raise DbEncryptionError(
                f"{db_path} is not readable as plaintext SQLite — configure "
                "VAULT_PORTAL_DB_ENCRYPTION_KEY / keys/db_encryption.key "
                "(SQLCipher)."
            )
        return

    if plaintext:
        raise DbEncryptionError(
            f"{db_path} is still plaintext but a SQLCipher key is configured. "
            "Run scripts/encrypt_portal_db.py before starting the app / Alembic."
        )