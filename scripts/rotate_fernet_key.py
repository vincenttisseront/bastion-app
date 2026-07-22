#!/usr/bin/env python3
"""Rotate the application-vault Fernet key (re-encrypt portal.db ciphertext columns).

Usage (keys via ephemeral env only — never CLI args visible in `ps`):

    OLD_FERNET_KEY=... NEW_FERNET_KEY=... python -m scripts.rotate_fernet_key

Optional:

    ROTATION_DB_PATH=/var/lib/sso-portal/portal.db   # override backup path
    SKIP_DB_BACKUP=1                                 # skip portal.db copy (tests)

Exit code non-zero on failure. Does NOT restore the DB backup automatically
(Phase 6 doctrine: failed smoke ≠ silent rollback).
"""

from __future__ import annotations

import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sqlalchemy.engine.url import make_url  # noqa: E402

from app.database import SessionLocal  # noqa: E402
from app.sso_settings import get_settings  # noqa: E402
from app.vault.key_rotation_service import (  # noqa: E402
    KeyRotationError,
    rotate_fernet_key,
)

ENV_OLD = "OLD_FERNET_KEY"
ENV_NEW = "NEW_FERNET_KEY"


def _sqlite_path(database_url: str) -> Path | None:
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite" or not url.database:
        return None
    return Path(url.database)


def _backup_portal_db(db_path: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = db_path.with_name(f"{db_path.name}.bak-pre-rotation-{stamp}")
    shutil.copy2(db_path, dest)
    os.chmod(dest, 0o640)
    return dest


def main() -> int:
    old_key = os.environ.get(ENV_OLD, "").strip()
    new_key = os.environ.get(ENV_NEW, "").strip()
    if not old_key or not new_key:
        print(
            f"ERROR: set {ENV_OLD} and {ENV_NEW} in the environment "
            "(never pass keys as CLI arguments).",
            file=sys.stderr,
        )
        return 2

    settings = get_settings()
    override = os.environ.get("ROTATION_DB_PATH", "").strip()
    db_path = Path(override) if override else _sqlite_path(settings.database_url)

    skip_backup = os.environ.get("SKIP_DB_BACKUP", "").strip() in ("1", "true", "yes")
    if not skip_backup:
        if db_path is None:
            print(
                "ERROR: cannot resolve SQLite path from DATABASE_URL; "
                "set ROTATION_DB_PATH or SKIP_DB_BACKUP=1.",
                file=sys.stderr,
            )
            return 2
        if not db_path.is_file():
            print(f"ERROR: database file not found: {db_path}", file=sys.stderr)
            return 2
        backup = _backup_portal_db(db_path)
        print(f"backup: {backup}")

    db = SessionLocal()
    try:
        report = rotate_fernet_key(db, old_key, new_key)
    except KeyRotationError as exc:
        print(f"ERROR: rotation failed: {exc}", file=sys.stderr)
        print(
            "Restore portal.db from bak-pre-rotation-* if needed; "
            "do not update AWX Vault until rotation succeeds.",
            file=sys.stderr,
        )
        return 1
    finally:
        db.close()

    print(
        "OK: rotation success "
        f"total={report.total} "
        f"app_credentials={report.app_credentials} "
        f"user_app_credentials={report.user_app_credentials} "
        f"realm_client_secrets={report.realm_client_secrets} "
        f"realm_oauth2_cookie_secrets={report.realm_oauth2_cookie_secrets} "
        f"realm_admin_client_secrets={report.realm_admin_client_secrets} "
        f"duration_ms={report.duration_ms:.1f}"
    )
    print(
        "Next: update AWX Vault vault_portal_vault_fernet_key, redeploy .env, "
        "restart bastion-app, then run smoke with sso_portal_post_rotation_smoke=true."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
