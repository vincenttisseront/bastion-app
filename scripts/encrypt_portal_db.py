#!/usr/bin/env python3
"""One-shot idempotent: convert plaintext portal.db → SQLCipher-encrypted file.

Must run BEFORE the first app/Alembic start that expects an encrypted DB.

Algorithm (SQLCipher sqlcipher_export):
  1. Backup plaintext → portal.db.bak-pre-sqlcipher-{timestamp}
  2. ATTACH encrypted DB WITH KEY, SELECT sqlcipher_export('encrypted')
  3. Atomic replace of portal.db

Idempotent: if the file is already encrypted (not plaintext-readable), exit 0.
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.db_cipher import (  # noqa: E402
    DbEncryptionError,
    apply_pragma_key,
    normalize_db_encryption_key,
    probe_plaintext_readable,
    resolve_db_encryption_key,
    sqlite_path_from_url,
)
from app.sso_settings import get_settings  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("encrypt_portal_db")


def _import_sqlcipher():
    try:
        import sqlcipher3

        return sqlcipher3
    except ImportError as exc:
        raise SystemExit(
            "sqlcipher3 required for encrypt_portal_db.py "
            "(pip install sqlcipher3-binary on Linux)"
        ) from exc


def _verify_encrypted(path: Path, key_hex: str) -> None:
    sqlcipher3 = _import_sqlcipher()
    conn = sqlcipher3.connect(str(path))
    try:
        apply_pragma_key(conn, key_hex)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if not tables:
            raise DbEncryptionError(f"encrypted DB has no tables: {path}")
        logger.info("verified encrypted DB tables=%s", sorted(tables)[:12])
    finally:
        conn.close()


def encrypt_database(db_path: Path, key_hex: str) -> int:
    """Encrypt in place via export to a sibling file, then atomic replace. Returns 0."""
    key_hex = normalize_db_encryption_key(key_hex)
    sqlcipher3 = _import_sqlcipher()

    if not db_path.is_file():
        logger.info("database file does not exist — nothing to encrypt (%s)", db_path)
        return 0

    if db_path.stat().st_size == 0:
        logger.info("database file empty — nothing to encrypt")
        return 0

    if not probe_plaintext_readable(db_path):
        logger.info("database already encrypted (or unreadable as plaintext) — skip")
        return 0

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = db_path.with_name(f"{db_path.name}.bak-pre-sqlcipher-{stamp}")
    encrypted = db_path.with_name(f"{db_path.name}.sqlcipher-tmp-{stamp}")
    if encrypted.exists():
        encrypted.unlink()

    logger.info("backing up plaintext to %s", backup)
    shutil.copy2(db_path, backup)
    try:
        os.chmod(backup, 0o600)
    except OSError:
        pass

    logger.info("exporting SQLCipher copy → %s", encrypted)
    # Open plaintext with SQLCipher driver (no key) — source stays untouched.
    src = sqlcipher3.connect(str(db_path))
    try:
        # ATTACH with raw key; double single-quotes inside SQL string for x'..'
        src.execute(
            f"ATTACH DATABASE '{encrypted.as_posix()}' AS encrypted "
            f"KEY \"x'{key_hex}'\""
        )
        src.execute("SELECT sqlcipher_export('encrypted')")
        src.execute("DETACH DATABASE encrypted")
    finally:
        src.close()

    _verify_encrypted(encrypted, key_hex)

    # Atomic replace on same filesystem
    os.replace(encrypted, db_path)
    logger.info("replaced %s with encrypted database", db_path)

    if probe_plaintext_readable(db_path):
        raise DbEncryptionError(
            "post-replace portal.db is still plaintext-readable — abort"
        )
    _verify_encrypted(db_path, key_hex)
    logger.info(
        "encryption OK; keep plaintext backup %s until smoke validation, "
        "then store offline",
        backup,
    )
    return 0


def main() -> int:
    get_settings.cache_clear()
    settings = get_settings()
    try:
        key_hex = resolve_db_encryption_key(settings)
    except DbEncryptionError as exc:
        logger.error("%s", exc)
        return 1

    if not key_hex:
        logger.warning(
            "no VAULT_PORTAL_DB_ENCRYPTION_KEY / keys/db_encryption.key — "
            "skipping SQLCipher conversion (plaintext mode)"
        )
        return 0

    try:
        db_path = sqlite_path_from_url(settings.database_url)
    except DbEncryptionError as exc:
        logger.error("%s", exc)
        return 1

    logger.info("database: %s", db_path)
    try:
        return encrypt_database(db_path, key_hex)
    except DbEncryptionError as exc:
        logger.error("%s", exc)
        return 1
    except Exception:
        logger.exception("encrypt_portal_db failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
