#!/usr/bin/env python3
"""One-shot idempotent repair for audit_logs schema drift (legacy portal → bastion-app)."""

from __future__ import annotations

import logging
import sqlite3
import sys
from pathlib import Path

# Allow running from repo root or /opt/sso-portal
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.sso_settings import get_settings  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("fix_audit_logs_schema")

TABLE = "audit_logs"

# Columns required by app.models.AuditLog (bastion-app)
REQUIRED_COLUMNS: dict[str, str] = {
    "actor": "TEXT",
    "action": "TEXT",
    "target": "TEXT",
    "details": "TEXT",
    "ip_address": "TEXT",
    "created_at": "TEXT",
}


def _sqlite_path_from_url(database_url: str) -> Path:
    if not database_url.startswith("sqlite"):
        raise SystemExit(f"Only sqlite DATABASE_URL supported, got: {database_url}")
    path = database_url.split("///", 1)[-1]
    return Path(path)


def _existing_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {row[1] for row in rows}


def _backfill_actor_from_legacy(conn: sqlite3.Connection) -> int:
    cols = _existing_columns(conn, TABLE)
    if "actor" not in cols:
        return 0
    updates = 0
    if "actor_username" in cols:
        cur = conn.execute(
            f"""
            UPDATE {TABLE}
            SET actor = COALESCE(NULLIF(actor, ''), actor_username)
            WHERE (actor IS NULL OR actor = '') AND actor_username IS NOT NULL
            """
        )
        updates += cur.rowcount
    if "actor_email" in cols:
        cur = conn.execute(
            f"""
            UPDATE {TABLE}
            SET actor = COALESCE(NULLIF(actor, ''), actor_email)
            WHERE (actor IS NULL OR actor = '') AND actor_email IS NOT NULL
            """
        )
        updates += cur.rowcount
    return updates


def _backfill_ip_from_legacy(conn: sqlite3.Connection) -> int:
    cols = _existing_columns(conn, TABLE)
    if "ip_address" not in cols or "client_ip" not in cols:
        return 0
    cur = conn.execute(
        f"""
        UPDATE {TABLE}
        SET ip_address = client_ip
        WHERE (ip_address IS NULL OR ip_address = '') AND client_ip IS NOT NULL
        """
    )
    return cur.rowcount


def main() -> int:
    get_settings.cache_clear()
    settings = get_settings()
    db_path = _sqlite_path_from_url(settings.database_url)
    logger.info("database: %s", db_path)

    if not db_path.exists():
        logger.info("database file does not exist — nothing to fix")
        return 0

    conn = sqlite3.connect(db_path)
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if TABLE not in tables:
            logger.info("table %s does not exist — will be created by Alembic/app startup", TABLE)
            return 0

        existing = _existing_columns(conn, TABLE)
        logger.info("existing columns: %s", sorted(existing))

        added: list[str] = []
        for column, col_type in REQUIRED_COLUMNS.items():
            if column in existing:
                logger.info("column %s already present", column)
                continue
            sql = f"ALTER TABLE {TABLE} ADD COLUMN {column} {col_type}"
            logger.info("executing: %s", sql)
            conn.execute(sql)
            added.append(column)

        actor_backfill = _backfill_actor_from_legacy(conn)
        ip_backfill = _backfill_ip_from_legacy(conn)
        conn.commit()

        if added:
            logger.info("added columns: %s", added)
        else:
            logger.info("schema already compliant — no columns added")

        if actor_backfill:
            logger.info("backfilled actor from legacy columns: %d rows", actor_backfill)
        if ip_backfill:
            logger.info("backfilled ip_address from client_ip: %d rows", ip_backfill)

        final = sorted(_existing_columns(conn, TABLE))
        logger.info("final columns: %s", final)
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
