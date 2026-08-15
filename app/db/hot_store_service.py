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
    provision_hot_role_and_database,
    reset_hot_table_sequences,
    resolve_hot_password,
    set_hot_enabled_cache,
    sync_hot_engine_from_config,
    test_hot_connection,
)
from app.models import PortalSettings, utcnow
from app.portal_settings_service import ensure_portal_settings
from app.secret_crypto import decrypt_secret, encrypt_secret, encryption_configured
from app.sso_settings import Settings

logger = logging.getLogger(__name__)


def _fmt_dt(dt) -> str:
    if dt is None:
        return "—"
    try:
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(dt)


def _clear_test_state(row: PortalSettings) -> None:
    row.hot_store_last_test_at = None
    row.hot_store_last_test_ok = None
    row.hot_store_last_test_ms = None
    row.hot_store_last_test_error = None


def _clear_schema_and_downstream(row: PortalSettings) -> None:
    row.hot_store_schema_prepared_at = None
    row.hot_store_schema_prepared_by = None
    row.hot_store_last_migrate_at = None
    row.hot_store_last_migrate_summary = None
    row.hot_store_migrate_skipped_at = None
    row.hot_store_migrate_skipped_by = None


def _require_configured(row: PortalSettings) -> None:
    if not (row.hot_store_host or "").strip():
        raise HotStoreError("Configurez d’abord l’hôte PostgreSQL")


def _hot_dsn_from_row(row: PortalSettings, settings: Settings) -> str:
    _require_configured(row)
    password = resolve_hot_password(
        row,
        decrypt_password=lambda enc: decrypt_secret(enc, settings),
        env_password=getattr(settings, "hot_store_pg_password", ""),
    )
    return build_hot_dsn(
        host=row.hot_store_host or "",
        port=int(row.hot_store_port or 5432),
        database=row.hot_store_database or "bastion_hot",
        user=row.hot_store_user or "bastion_hot",
        password=password,
        sslmode=row.hot_store_sslmode or "prefer",
    )


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

    prev_host = (row.hot_store_host or "").strip()
    prev_port = int(row.hot_store_port or 5432) if row.hot_store_port else 5432
    prev_db = (row.hot_store_database or "").strip()
    prev_user = (row.hot_store_user or "").strip()
    endpoint_changed = (
        prev_host != host
        or prev_port != port_i
        or prev_db != database
        or prev_user != user
    )

    row.hot_store_host = host
    row.hot_store_port = port_i
    row.hot_store_database = database
    row.hot_store_user = user
    row.hot_store_sslmode = sslmode
    if (password or "").strip():
        row.hot_store_password_encrypted = encrypt_secret(password.strip(), settings)
    # Force a fresh connection test after any save.
    _clear_test_state(row)
    if endpoint_changed:
        _clear_schema_and_downstream(row)
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
            "endpoint_changed": endpoint_changed,
            "wizard_reset": endpoint_changed,
        },
        ip_address=ip_address,
    )
    return row


def provision_hot_store(
    db: Session,
    settings: Settings,
    *,
    host: str,
    port: int,
    database: str,
    user: str,
    password: str,
    sslmode: str,
    admin_user: str,
    admin_password: str,
    admin_database: str = "",
    actor: str,
    ip_address: str | None = None,
) -> dict[str, Any]:
    """Create/align PG role+database, then persist app connection settings."""
    if not encryption_configured(settings):
        raise HotStoreError(
            "Chiffrement Fernet requis pour stocker le mot de passe PostgreSQL"
        )
    password = (password or "").strip()
    if not password:
        # Blank field means "align the role on the password already in use" —
        # the environment one, so provisioning cannot re-create the drift.
        row = ensure_portal_settings(db, settings)
        password = resolve_hot_password(
            row,
            decrypt_password=lambda enc: decrypt_secret(enc, settings),
            env_password=getattr(settings, "hot_store_pg_password", ""),
        )
        if not password:
            raise HotStoreError(
                "Mot de passe du rôle hot store requis (champ « Mot de passe » "
                "ou HOT_STORE_PG_PASSWORD dans le .env)"
            )
    admin_password = (admin_password or "").strip()
    if not admin_password:
        raise HotStoreError(
            "Mot de passe admin PostgreSQL requis pour créer/aligner le rôle et la base"
        )
    admin_user = (admin_user or "").strip() or "postgres"

    result = provision_hot_role_and_database(
        host=host,
        port=port,
        sslmode=sslmode,
        admin_user=admin_user,
        admin_password=admin_password,
        database=database,
        user=user,
        password=password,
        admin_database=(admin_database or "").strip() or None,
    )

    save_hot_store_config(
        db,
        settings,
        host=host,
        port=port,
        database=database,
        user=user,
        password=password,
        sslmode=sslmode,
        actor=actor,
        ip_address=ip_address,
    )
    # Mark connection test OK after successful verify inside provision.
    row = ensure_portal_settings(db, settings)
    row.hot_store_last_test_at = utcnow()
    row.hot_store_last_test_ok = True
    row.hot_store_last_test_ms = result.get("ping_ms")
    row.hot_store_last_test_error = None
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()

    log_action(
        db,
        actor=actor,
        action="hot_store.provisioned",
        target="portal_settings",
        details={
            "host": (host or "").strip(),
            "database": result.get("database"),
            "user": result.get("user"),
            "role_created": result.get("role_created"),
            "database_created": result.get("database_created"),
            "role_password_set": result.get("role_password_set"),
            "admin_user": admin_user,
            "admin_database": result.get("admin_database"),
        },
        ip_address=ip_address,
    )
    return result


def test_hot_store_config(
    db: Session,
    settings: Settings,
    *,
    actor: str | None = None,
    ip_address: str | None = None,
) -> dict[str, Any]:
    row = ensure_portal_settings(db, settings)
    _require_configured(row)
    dsn = _hot_dsn_from_row(row, settings)
    try:
        result = test_hot_connection(dsn)
        row.hot_store_last_test_at = utcnow()
        row.hot_store_last_test_ok = True
        row.hot_store_last_test_ms = result.get("ping_ms")
        row.hot_store_last_test_error = None
        row.updated_at = utcnow()
        if actor:
            row.updated_by = actor
        db.commit()
        if actor:
            log_action(
                db,
                actor=actor,
                action="hot_store.connection_tested",
                target="portal_settings",
                details={
                    "ok": True,
                    "ping_ms": result.get("ping_ms"),
                    "can_create": result.get("can_create"),
                    "version": (result.get("version") or "")[:80],
                },
                ip_address=ip_address,
            )
        return result
    except Exception as exc:
        row.hot_store_last_test_at = utcnow()
        row.hot_store_last_test_ok = False
        row.hot_store_last_test_ms = None
        row.hot_store_last_test_error = str(exc)[:500]
        row.updated_at = utcnow()
        if actor:
            row.updated_by = actor
        db.commit()
        if actor:
            log_action(
                db,
                actor=actor,
                action="hot_store.connection_tested",
                target="portal_settings",
                details={"ok": False, "error": str(exc)[:300]},
                ip_address=ip_address,
            )
        if isinstance(exc, HotStoreError):
            raise
        raise HotStoreError(str(exc)) from exc


def prepare_hot_store_schema(
    db: Session,
    settings: Settings,
    *,
    actor: str | None = None,
    ip_address: str | None = None,
    force: bool = False,
) -> None:
    """
    Create hot tables on PostgreSQL.

    After a successful prepare, further calls are refused unless ``force=True``
    (reserved for advanced/support paths — not exposed by the normal admin UI).
    """
    row = ensure_portal_settings(db, settings)
    _require_configured(row)
    if (row.hot_store_schema_prepared_at or row.hot_store_last_migrate_at) and not force:
        when = _fmt_dt(row.hot_store_schema_prepared_at or row.hot_store_last_migrate_at)
        raise HotStoreError(
            f"Schéma déjà initialisé le {when} — réinitialisation refusée. "
            "Pour réinitialiser, contactez le support ou utilisez une action "
            "avancée hors du parcours normal."
        )
    if not row.hot_store_last_test_ok:
        raise HotStoreError(
            "Réussissez d’abord le test de connexion avant de préparer le schéma"
        )

    eng = sync_hot_engine_from_config(db, settings)
    if eng is None:
        dsn = _hot_dsn_from_row(row, settings)
        eng = ensure_hot_engine(dsn)
    prepare_hot_schema(eng)

    row.hot_store_schema_prepared_at = utcnow()
    row.hot_store_schema_prepared_by = actor
    row.updated_at = utcnow()
    if actor:
        row.updated_by = actor
    db.commit()
    if actor:
        log_action(
            db,
            actor=actor,
            action="hot_store.schema_prepared",
            target="portal_settings",
            details={"prepared_at": _fmt_dt(row.hot_store_schema_prepared_at)},
            ip_address=ip_address,
        )


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
    if not row.hot_store_schema_prepared_at and not row.hot_store_last_migrate_at:
        raise HotStoreError("Préparez d’abord le schéma PostgreSQL")

    eng = sync_hot_engine_from_config(db, settings)
    if eng is None:
        dsn = _hot_dsn_from_row(row, settings)
        eng = ensure_hot_engine(dsn)
    # Idempotent low-level ensure (does not bypass portal_settings schema lock).
    prepare_hot_schema(eng)
    counts = migrate_all_hot_tables(db, eng)
    summary = json.dumps(counts, sort_keys=True)
    row.hot_store_last_migrate_at = utcnow()
    row.hot_store_last_migrate_summary = summary
    row.hot_store_migrate_skipped_at = None
    row.hot_store_migrate_skipped_by = None
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


def skip_hot_store_migrate(
    db: Session,
    settings: Settings,
    *,
    actor: str,
    ip_address: str | None = None,
) -> PortalSettings:
    """Mark the optional migration step as skipped (fresh Postgres, no SQLite history)."""
    row = ensure_portal_settings(db, settings)
    if not row.hot_store_schema_prepared_at and not row.hot_store_last_migrate_at:
        raise HotStoreError("Préparez d’abord le schéma PostgreSQL")
    if bool(getattr(row, "hot_store_enabled", False)):
        raise HotStoreError("Désactivez le hot store avant de modifier cette étape")
    row.hot_store_migrate_skipped_at = utcnow()
    row.hot_store_migrate_skipped_by = actor
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="hot_store.migrate_skipped",
        target="portal_settings",
        details={"skipped_at": _fmt_dt(row.hot_store_migrate_skipped_at)},
        ip_address=ip_address,
    )
    return row


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
        _require_configured(row)
        if not row.hot_store_schema_prepared_at and not row.hot_store_last_migrate_at:
            raise HotStoreError("Préparez d’abord le schéma PostgreSQL")
        if not row.hot_store_last_migrate_at and not row.hot_store_migrate_skipped_at:
            raise HotStoreError(
                "Migrez les données ou passez explicitement l’étape de migration"
            )
        result = test_hot_store_config(db, settings, actor=actor, ip_address=ip_address)
        if not result.get("ok"):
            raise HotStoreError("Connexion PostgreSQL en échec — activation refusée")
        eng = sync_hot_engine_from_config(db, settings)
        if eng is None:
            raise HotStoreError("Impossible d’ouvrir le moteur PostgreSQL")
        prepare_hot_schema(eng)
        try:
            reset_hot_table_sequences(eng)
        except Exception:
            logger.exception("hot store: sequence realign before enable failed")
        row = ensure_portal_settings(db, settings)

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
