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
from dataclasses import dataclass
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


@dataclass(frozen=True)
class DbEncryptionStatus:
    """Read-only status for Admin → Sécurité (never includes key material)."""

    enabled: bool
    key_file_present: bool
    env_configured: bool
    source: str | None  # file | env | None
    db_path: str | None
    db_exists: bool
    db_encrypted: bool | None
    sqlcipher_available: bool
    status_badge: str  # ok | warn | muted | error
    status_label: str
    keys_dir: str


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
    from sqlalchemy.pool import NullPool

    from app.sso_settings import get_settings

    cfg = settings or get_settings()
    key_hex = resolve_db_encryption_key(cfg)
    connect_args = dict(kwargs.pop("connect_args", {}) or {})
    connect_args.setdefault("check_same_thread", False)

    engine_kwargs: dict = {
        "connect_args": connect_args,
        **kwargs,
    }

    # SQLAlchemy 2.0 defaults sqlite to QueuePool(5+10); under concurrent
    # auth_request that exhausts instantly. File sqlite must use NullPool.
    # Tests may pass StaticPool / QueuePool explicitly — respect that.
    if "poolclass" not in engine_kwargs and "pool" not in engine_kwargs:
        if (database_url or "").strip().lower().startswith("sqlite"):
            engine_kwargs["poolclass"] = NullPool
        else:
            engine_kwargs.setdefault("pool_size", 20)
            engine_kwargs.setdefault("max_overflow", 40)
            engine_kwargs.setdefault("pool_pre_ping", True)

    assert_db_cipher_state(database_url, key_hex)

    if key_hex is not None:
        sqlcipher3 = _import_sqlcipher()
        engine_kwargs["module"] = sqlcipher3
        engine = create_engine(database_url, **engine_kwargs)
        _register_key_on_connect(engine, key_hex)
        with engine.connect() as conn:
            verify_db_readable(conn)
        logger.info("SQLCipher enabled for portal database")
    else:
        engine = create_engine(database_url, **engine_kwargs)

    if (database_url or "").strip().lower().startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _sqlite_busy_timeout(dbapi_connection, _connection_record) -> None:  # noqa: ANN001
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA busy_timeout=5000")
            finally:
                cursor.close()

    return engine


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

def _sqlcipher_available() -> bool:
    try:
        import importlib.util

        return importlib.util.find_spec("sqlcipher3") is not None
    except Exception:
        return False


def get_db_encryption_status(settings: Settings) -> DbEncryptionStatus:
    """Build UI status for SQLCipher at-rest encryption (no key material exposed)."""
    keys_dir = resolve_keys_dir(settings)
    key_path = keys_dir / DB_ENCRYPTION_KEY_FILENAME
    key_file_present = False
    if key_path.is_file():
        try:
            key_file_present = bool(key_path.read_text(encoding="ascii").strip())
        except OSError:
            key_file_present = False
    env_configured = bool((settings.vault_portal_db_encryption_key or "").strip())
    enabled = key_file_present or env_configured
    if key_file_present:
        source: str | None = "file"
    elif env_configured:
        source = "env"
    else:
        source = None

    sqlcipher_ok = _sqlcipher_available()
    db_path: str | None = None
    db_exists = False
    db_encrypted: bool | None = None

    if not is_memory_database_url(settings.database_url):
        try:
            path = sqlite_path_from_url(settings.database_url)
            db_path = str(path)
            if path.is_file() and path.stat().st_size > 0:
                db_exists = True
                db_encrypted = not probe_plaintext_readable(path)
        except DbEncryptionError:
            db_path = settings.database_url

    if not enabled:
        if db_exists and db_encrypted:
            badge, label = "error", "Clé manquante"
        else:
            badge, label = "muted", "Désactivé (fichier en clair)"
    elif not sqlcipher_ok:
        badge, label = "error", "Driver SQLCipher manquant"
    elif db_exists and db_encrypted is False:
        badge, label = "warn", "Migration requise"
    elif db_exists and db_encrypted:
        badge, label = "ok", "Actif"
    else:
        badge, label = "ok", "Prêt"

    return DbEncryptionStatus(
        enabled=enabled,
        key_file_present=key_file_present,
        env_configured=env_configured,
        source=source,
        db_path=db_path,
        db_exists=db_exists,
        db_encrypted=db_encrypted,
        sqlcipher_available=sqlcipher_ok,
        status_badge=badge,
        status_label=label,
        keys_dir=str(keys_dir),
    )
