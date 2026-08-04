"""Admin operations for the optional PostgreSQL hot store."""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.audit import log_action
from app.db.hot_store import (
    HOT_TABLE_NAMES,
    HotStoreError,
    build_hot_dsn,
    dispose_hot_engine,
    ensure_hot_engine,
    invalidate_hot_enabled_cache,
    migrate_all_hot_tables,
    prepare_hot_schema,
    set_hot_enabled_cache,
    sync_hot_engine_from_config,
    test_hot_connection,
)
from app.models import PortalSettings, utcnow
from app.portal_settings_service import ensure_portal_settings
from app.secret_crypto import decrypt_secret, encrypt_secret, encryption_configured
from app.sso_settings import Settings

logger = logging.getLogger(__name__)


def save_hot_store_config(
    db: Session,
    settings: Settings,
    *,
    host: str,
    port: int,
    database: str,
    user: str,
    password: str,
    sslmode: str,
    actor: str,
    ip_address: str | None = None,
) -> PortalSettings:
    """Persist hot-store connection settings (password empty = keep existing)."""
    if not encryption_configured(settings):
        raise HotStoreError(
            "Chiffrement Fernet requis pour stocker le mot de passe PostgreSQL"
        )
    row = ensure_portal_settings(db, settings)
    host = (host or "").strip()
    database = (database or "").strip() or "bastion_hot"
    user = (user or "").strip() or "bastion_hot"
    sslmode = (sslmode or "prefer").strip() or "prefer"
    if sslmode not in ("prefer", "require", "disable", "allow", "verify-ca", "verify-full"):
        raise HotStoreError(f"sslmode invalide : {sslmode}")
    try:
        port_i = int(port or 5432)
    except (TypeError, ValueError) as exc:
        raise HotStoreError("Port PostgreSQL invalide") from exc
    if not host:
        raise HotStoreError("Hôte PostgreSQL requis")

    row.hot_store_host = host
    row.hot_store_port = port_i
    row.hot_store_database = database
    row.hot_store_user = user
    row.hot_store_sslmode = sslmode
    if (password or "").strip():
        row.hot_store_password_encrypted = encrypt_secret(password.strip(), settings)
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)
    dispose_hot_engine()
    invalidate_hot_enabled_cache()
    sync_hot_engine_from_config(db, settings)
    log_action(
        db,
        actor=actor,
        action="hot_store.config_saved",
        target="portal_settings",
        details={
            "host": host,
            "port": port_i,
            "database": database,
            "user": user,
            "sslmode": sslmode,
            "password_updated": bool((password or "").strip()),
        },
        ip_address=ip_address,
    )
    return row


def test_hot_store_config(db: Session, settings: Settings) -> dict[str, Any]:
    row = ensure_portal_settings(db, settings)
    if not (row.hot_store_host or "").strip():
        raise HotStoreError("Configurez d’abord l’hôte PostgreSQL")
    password = ""
    if row.hot_store_password_encrypted:
        password = decrypt_secret(row.hot_store_password_encrypted, settings) or ""
    dsn = build_hot_dsn(
        host=row.hot_store_host or "",
        port=int(row.hot_store_port or 5432),
        database=row.hot_store_database or "bastion_hot",
        user=row.hot_store_user or "bastion_hot",
        password=password,
        sslmode=row.hot_store_sslmode or "prefer",
    )
    return test_hot_connection(dsn)


def prepare_hot_store_schema(db: Session, settings: Settings) -> None:
    eng = sync_hot_engine_from_config(db, settings)
    if eng is None:
        # Force create from saved settings
        row = ensure_portal_settings(db, settings)
        if not (row.hot_store_host or "").strip():
            raise HotStoreError("Hot store non configuré")
        password = ""
        if row.hot_store_password_encrypted:
            password = decrypt_secret(row.hot_store_password_encrypted, settings) or ""
        dsn = build_hot_dsn(
            host=row.hot_store_host or "",
            port=int(row.hot_store_port or 5432),
            database=row.hot_store_database or "bastion_hot",
            user=row.hot_store_user or "bastion_hot",
            password=password,
            sslmode=row.hot_store_sslmode or "prefer",
        )
        eng = ensure_hot_engine(dsn)
    prepare_hot_schema(eng)


def run_hot_store_migrate(
    db: Session,
    settings: Settings,
    *,
    actor: str,
    ip_address: str | None = None,
) -> dict[str, int]:
    """Copy hot tables from SQLite config DB into Postgres (full replace per table)."""
    row = ensure_portal_settings(db, settings)
    if bool(getattr(row, "hot_store_enabled", False)):
        raise HotStoreError(
            "Désactivez le hot store avant de re-migrer (évite les écritures concurrentes)"
        )
    prepare_hot_store_schema(db, settings)
    eng = sync_hot_engine_from_config(db, settings)
    if eng is None:
        raise HotStoreError("Impossible d’ouvrir le moteur PostgreSQL")
    counts = migrate_all_hot_tables(db, eng)
    summary = json.dumps(counts, sort_keys=True)
    row.hot_store_last_migrate_at = utcnow()
    row.hot_store_last_migrate_summary = summary
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    log_action(
        db,
        actor=actor,
        action="hot_store.migrate",
        target="portal_settings",
        details={"tables": counts, "table_names": list(HOT_TABLE_NAMES)},
        ip_address=ip_address,
    )
    return counts


def set_hot_store_enabled(
    db: Session,
    settings: Settings,
    enabled: bool,
    *,
    actor: str,
    ip_address: str | None = None,
) -> PortalSettings:
    row = ensure_portal_settings(db, settings)
    new_value = bool(enabled)
    if new_value:
        if not (row.hot_store_host or "").strip():
            raise HotStoreError("Configurez PostgreSQL avant d’activer le hot store")
        if not row.hot_store_last_migrate_at:
            raise HotStoreError("Migrez les tables chaudes avant d’activer le hot store")
        # Verify connectivity + schema
        prepare_hot_store_schema(db, settings)
        result = test_hot_store_config(db, settings)
        if not result.get("ok"):
            raise HotStoreError("Connexion PostgreSQL en échec — activation refusée")

    previous = bool(getattr(row, "hot_store_enabled", False))
    row.hot_store_enabled = new_value
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)
    set_hot_enabled_cache(new_value)
    if new_value:
        sync_hot_engine_from_config(db, settings)
    else:
        # Keep engine for re-enable / remigrate; only clear enabled flag.
        invalidate_hot_enabled_cache()
        set_hot_enabled_cache(False)
    log_action(
        db,
        actor=actor,
        action="hot_store.enabled" if new_value else "hot_store.disabled",
        target="portal_settings",
        details={"previous": previous, "new": new_value},
        ip_address=ip_address,
    )
    return row
