"""Optional PostgreSQL hot store for high-volume tables.

SQLite (SQLCipher) remains the configuration database. When enabled via Admin →
Sécurité, selected hot tables are read/written on a separate Postgres engine.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable, Sequence
from urllib.parse import quote_plus

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from app.models import (
    ActiveSession,
    AuditLog,
    Base,
    BreakGlassSession,
    OidcLoginAttempt,
    OidcSession,
    SecurityRateEvent,
    SiemOutboxEntry,
    SsoSessionAnchor,
)

logger = logging.getLogger(__name__)

HOT_MODELS: tuple[type, ...] = (
    OidcSession,
    OidcLoginAttempt,
    ActiveSession,
    SsoSessionAnchor,
    BreakGlassSession,
    SecurityRateEvent,
    AuditLog,
    SiemOutboxEntry,
)

HOT_TABLE_NAMES: tuple[str, ...] = tuple(m.__tablename__ for m in HOT_MODELS)

_HOT_MODEL_SET = frozenset(HOT_MODELS)

# Process-wide hot engine cache (rebuilt when DSN fingerprint changes).
_lock = threading.RLock()
_hot_engine: Engine | None = None
_hot_engine_dsn: str | None = None
_hot_enabled_cache: bool = False
_hot_enabled_checked_at: float = 0.0
_HOT_ENABLED_TTL_SEC = 5.0

HOT_SCHEMA_VERSION = 1

# Safe SQL identifiers for CREATE ROLE / CREATE DATABASE (no quoting gymnastics).
_PG_IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")


class HotStoreError(RuntimeError):
    """Configuration or migration error for the hot store."""


def validate_pg_identifier(name: str, *, label: str) -> str:
    """Reject anything that cannot be a bare PostgreSQL identifier."""
    value = (name or "").strip()
    if not value or not _PG_IDENT_RE.match(value):
        raise HotStoreError(
            f"{label} invalide : utilisez uniquement lettres, chiffres et "
            f"underscore (max 63), sans commencer par un chiffre."
        )
    return value


def is_hot_model(model: type | None) -> bool:
    return model is not None and model in _HOT_MODEL_SET


def build_hot_dsn(
    *,
    host: str,
    port: int,
    database: str,
    user: str,
    password: str,
    sslmode: str = "prefer",
) -> str:
    """Assemble a postgresql+psycopg DSN (password never logged by callers)."""
    host = (host or "").strip()
    database = (database or "").strip()
    user = (user or "").strip()
    if not host or not database or not user:
        raise HotStoreError("Hôte, base et utilisateur PostgreSQL sont requis")
    port = int(port or 5432)
    ssl = (sslmode or "prefer").strip() or "prefer"
    user_q = quote_plus(user)
    pass_q = quote_plus(password or "")
    return (
        f"postgresql+psycopg://{user_q}:{pass_q}@{host}:{port}/{database}"
        f"?sslmode={quote_plus(ssl)}"
    )


def create_hot_engine(dsn: str, **kwargs: Any) -> Engine:
    """Create a pooled Postgres engine (never SQLCipher / sqlite connect_args)."""
    dsn = (dsn or "").strip()
    if not dsn:
        raise HotStoreError("DSN hot store vide")
    if dsn.lower().startswith("sqlite"):
        raise HotStoreError("Le hot store doit être PostgreSQL, pas SQLite")

    connect_args = dict(kwargs.pop("connect_args", None) or {})
    engine_kwargs: dict[str, Any] = {**kwargs}
    if "poolclass" not in engine_kwargs and "pool" not in engine_kwargs:
        engine_kwargs.setdefault("pool_size", 20)
        engine_kwargs.setdefault("max_overflow", 40)
        engine_kwargs.setdefault("pool_pre_ping", True)

    if connect_args:
        engine_kwargs["connect_args"] = connect_args

    engine = create_engine(dsn, **engine_kwargs)

    @event.listens_for(engine, "connect")
    def _pg_timeouts(dbapi_connection, _connection_record) -> None:  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("SET statement_timeout = '30s'")
            cursor.execute("SET lock_timeout = '5s'")
        except Exception:
            logger.debug("hot store: could not set PG timeouts", exc_info=True)
        finally:
            cursor.close()

    return engine


def dispose_hot_engine() -> None:
    global _hot_engine, _hot_engine_dsn
    with _lock:
        if _hot_engine is not None:
            try:
                _hot_engine.dispose()
            except Exception:
                logger.exception("hot store: dispose failed")
        _hot_engine = None
        _hot_engine_dsn = None


def get_cached_hot_engine() -> Engine | None:
    with _lock:
        return _hot_engine


def ensure_hot_engine(dsn: str) -> Engine:
    """Return a live hot engine for ``dsn``, recreating if the DSN changed."""
    global _hot_engine, _hot_engine_dsn
    dsn = (dsn or "").strip()
    if not dsn:
        raise HotStoreError("DSN hot store vide")
    with _lock:
        if _hot_engine is not None and _hot_engine_dsn == dsn:
            return _hot_engine
        if _hot_engine is not None:
            try:
                _hot_engine.dispose()
            except Exception:
                logger.exception("hot store: dispose before recreate failed")
        _hot_engine = create_hot_engine(dsn)
        _hot_engine_dsn = dsn
        return _hot_engine


def set_hot_enabled_cache(enabled: bool) -> None:
    global _hot_enabled_cache, _hot_enabled_checked_at
    with _lock:
        _hot_enabled_cache = bool(enabled)
        _hot_enabled_checked_at = time.monotonic()


def invalidate_hot_enabled_cache() -> None:
    global _hot_enabled_checked_at
    with _lock:
        _hot_enabled_checked_at = 0.0


def _read_hot_enabled_from_config_session(db: Session) -> bool:
    from app.models import PortalSettings
    from app.portal_settings_service import PORTAL_SETTINGS_ID

    row = db.query(PortalSettings).filter_by(id=PORTAL_SETTINGS_ID).first()
    return bool(row and getattr(row, "hot_store_enabled", False))


def hot_store_runtime_enabled(config_db: Session | None = None) -> bool:
    """Fast path: cached flag. Optional config_db refreshes cache when stale."""
    global _hot_enabled_cache, _hot_enabled_checked_at
    now = time.monotonic()
    with _lock:
        fresh = (now - _hot_enabled_checked_at) < _HOT_ENABLED_TTL_SEC
        if fresh:
            return _hot_enabled_cache
    if config_db is None:
        with _lock:
            return _hot_enabled_cache
    enabled = _read_hot_enabled_from_config_session(config_db)
    set_hot_enabled_cache(enabled)
    return enabled


def resolve_hot_dsn_from_settings_row(row: Any, *, decrypt_password) -> str | None:
    """Build DSN from PortalSettings row; ``decrypt_password`` decrypts Fernet blob."""
    host = (getattr(row, "hot_store_host", None) or "").strip()
    if not host:
        return None
    port = int(getattr(row, "hot_store_port", None) or 5432)
    database = (getattr(row, "hot_store_database", None) or "").strip() or "bastion_hot"
    user = (getattr(row, "hot_store_user", None) or "").strip() or "bastion_hot"
    sslmode = (getattr(row, "hot_store_sslmode", None) or "prefer").strip() or "prefer"
    enc = getattr(row, "hot_store_password_encrypted", None)
    password = ""
    if enc:
        password = decrypt_password(enc) or ""
    return build_hot_dsn(
        host=host,
        port=port,
        database=database,
        user=user,
        password=password,
        sslmode=sslmode,
    )


def sync_hot_engine_from_config(config_db: Session, settings) -> Engine | None:
    """Load DSN from portal_settings; return engine if configured (enabled or not)."""
    from app.portal_settings_service import get_portal_settings_row
    from app.secret_crypto import decrypt_secret

    row = get_portal_settings_row(config_db)
    if row is None:
        set_hot_enabled_cache(False)
        dispose_hot_engine()
        return None
    enabled = bool(getattr(row, "hot_store_enabled", False))
    set_hot_enabled_cache(enabled)
    try:
        dsn = resolve_hot_dsn_from_settings_row(
            row,
            decrypt_password=lambda enc: decrypt_secret(enc, settings),
        )
    except Exception:
        logger.exception("hot store: cannot resolve DSN")
        return None
    if not dsn:
        dispose_hot_engine()
        return None
    try:
        return ensure_hot_engine(dsn)
    except Exception:
        logger.exception("hot store: cannot create engine")
        return None


def prepare_hot_schema(engine: Engine) -> None:
    """Create hot tables on the hot engine (idempotent)."""
    tables = [Base.metadata.tables[name] for name in HOT_TABLE_NAMES if name in Base.metadata.tables]
    Base.metadata.create_all(bind=engine, tables=tables, checkfirst=True)
    dialect = engine.dialect.name
    with engine.begin() as conn:
        if dialect == "postgresql":
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS hot_schema_version (
                        id INTEGER PRIMARY KEY,
                        version INTEGER NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
                )
            )
            conn.execute(
                text(
                    """
                    INSERT INTO hot_schema_version (id, version)
                    VALUES (1, :v)
                    ON CONFLICT (id) DO UPDATE SET
                        version = EXCLUDED.version,
                        updated_at = NOW()
                    """
                ),
                {"v": HOT_SCHEMA_VERSION},
            )
        else:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS hot_schema_version (
                        id INTEGER PRIMARY KEY,
                        version INTEGER NOT NULL,
                        updated_at TEXT
                    )
                    """
                )
            )
            conn.execute(
                text(
                    "INSERT OR REPLACE INTO hot_schema_version (id, version, updated_at) "
                    "VALUES (1, :v, CURRENT_TIMESTAMP)"
                ),
                {"v": HOT_SCHEMA_VERSION},
            )


def test_hot_connection(dsn: str) -> dict[str, Any]:
    """Ping Postgres and return version / create capability / latency."""
    engine = create_hot_engine(dsn, poolclass=NullPool)
    try:
        with engine.connect() as conn:
            t0 = time.perf_counter()
            ver = conn.execute(text("SELECT version()")).scalar()
            ping_ms = round((time.perf_counter() - t0) * 1000, 1)
            can_create = conn.execute(
                text(
                    "SELECT has_database_privilege(current_user, current_database(), 'CREATE')"
                )
            ).scalar()
            return {
                "ok": True,
                "version": str(ver or "")[:200],
                "can_create": bool(can_create),
                "ping_ms": ping_ms,
            }
    finally:
        engine.dispose()


def _pg_ident(name: str) -> str:
    """Double-quote a validated identifier for DDL."""
    return '"' + name.replace('"', '""') + '"'


def _connect_admin_engine(
    *,
    host: str,
    port: int,
    sslmode: str,
    admin_user: str,
    admin_password: str,
    admin_database: str | None = None,
    fallback_database: str | None = None,
) -> tuple[Engine, str]:
    """Open an admin connection to a maintenance DB (postgres / template1 / …)."""
    candidates: list[str] = []
    if (admin_database or "").strip():
        candidates.append(admin_database.strip())
    for name in ("postgres", "template1"):
        if name not in candidates:
            candidates.append(name)
    if (fallback_database or "").strip() and fallback_database.strip() not in candidates:
        candidates.append(fallback_database.strip())

    last_exc: Exception | None = None
    for dbname in candidates:
        dsn = build_hot_dsn(
            host=host,
            port=port,
            database=dbname,
            user=admin_user,
            password=admin_password,
            sslmode=sslmode,
        )
        engine = create_hot_engine(dsn, poolclass=NullPool)
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return engine, dbname
        except Exception as exc:
            last_exc = exc
            try:
                engine.dispose()
            except Exception:
                pass
            continue
    detail = str(last_exc)[:300] if last_exc else "inconnu"
    raise HotStoreError(
        "Connexion admin PostgreSQL impossible. Vérifiez l’utilisateur/mot de passe "
        "d’administration (souvent le POSTGRES_PASSWORD d’initialisation du volume "
        f"pgdata, car il ne change plus ensuite). Détail : {detail}"
    ) from last_exc


def provision_hot_role_and_database(
    *,
    host: str,
    port: int,
    sslmode: str,
    admin_user: str,
    admin_password: str,
    database: str,
    user: str,
    password: str,
    admin_database: str | None = None,
) -> dict[str, Any]:
    """Create/align PostgreSQL role + database for the hot store (idempotent).

    Connects with ``admin_user`` / ``admin_password`` (superuser or CREATEROLE),
    then ensures ``user`` exists with ``password``, and ``database`` exists
    owned by that role. Does not log passwords.
    """
    host = (host or "").strip()
    if not host:
        raise HotStoreError("Hôte PostgreSQL requis")
    admin_user = validate_pg_identifier(admin_user, label="Utilisateur admin")
    database = validate_pg_identifier(database, label="Base")
    user = validate_pg_identifier(user, label="Utilisateur")
    password = password or ""
    if not password.strip():
        raise HotStoreError("Mot de passe du rôle hot store requis pour le provisionnement")
    sslmode = (sslmode or "prefer").strip() or "prefer"
    try:
        port_i = int(port or 5432)
    except (TypeError, ValueError) as exc:
        raise HotStoreError("Port PostgreSQL invalide") from exc

    engine, connected_db = _connect_admin_engine(
        host=host,
        port=port_i,
        sslmode=sslmode,
        admin_user=admin_user,
        admin_password=admin_password or "",
        admin_database=admin_database,
        fallback_database=database,
    )
    role_created = False
    role_password_set = False
    database_created = False
    try:
        # CREATE DATABASE cannot run inside a transaction block.
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            role_exists = bool(
                conn.execute(
                    text("SELECT 1 FROM pg_roles WHERE rolname = :n"),
                    {"n": user},
                ).scalar()
            )
            lit = conn.execute(
                text("SELECT quote_literal(:pw)"),
                {"pw": password},
            ).scalar()
            if not lit:
                raise HotStoreError("Échec d’échappement du mot de passe PostgreSQL")
            role_sql = _pg_ident(user)

            # Create role early with the target password. If the role already
            # exists, delay ALTER PASSWORD until after grants — otherwise a
            # subsequent admin reconnect (same login) would fail with the old pwd.
            if not role_exists:
                conn.exec_driver_sql(
                    f"CREATE ROLE {role_sql} WITH LOGIN PASSWORD {lit}"
                )
                role_created = True
                role_password_set = True

            db_exists = bool(
                conn.execute(
                    text("SELECT 1 FROM pg_database WHERE datname = :n"),
                    {"n": database},
                ).scalar()
            )
            db_sql = _pg_ident(database)
            if not db_exists:
                conn.exec_driver_sql(
                    f"CREATE DATABASE {db_sql} OWNER {role_sql}"
                )
                database_created = True
            else:
                conn.exec_driver_sql(
                    f"GRANT ALL PRIVILEGES ON DATABASE {db_sql} TO {role_sql}"
                )
                try:
                    conn.exec_driver_sql(
                        f"ALTER DATABASE {db_sql} OWNER TO {role_sql}"
                    )
                except Exception:
                    logger.debug(
                        "hot store: ALTER DATABASE OWNER skipped (insufficient privilege)",
                        exc_info=True,
                    )

            conn.exec_driver_sql(
                f"GRANT ALL PRIVILEGES ON DATABASE {db_sql} TO {role_sql}"
            )

        # Schema privileges on the target DB (public) — still with admin password.
        target_dsn = build_hot_dsn(
            host=host,
            port=port_i,
            database=database,
            user=admin_user,
            password=admin_password or "",
            sslmode=sslmode,
        )
        target_engine = create_hot_engine(target_dsn, poolclass=NullPool)
        try:
            with target_engine.connect().execution_options(
                isolation_level="AUTOCOMMIT"
            ) as conn:
                conn.exec_driver_sql(f"GRANT ALL ON SCHEMA public TO {role_sql}")
                conn.exec_driver_sql(f"GRANT CREATE ON SCHEMA public TO {role_sql}")
                try:
                    conn.exec_driver_sql(
                        f"ALTER SCHEMA public OWNER TO {role_sql}"
                    )
                except Exception:
                    logger.debug(
                        "hot store: ALTER SCHEMA OWNER skipped",
                        exc_info=True,
                    )
        finally:
            target_engine.dispose()

        # Align password last so admin reconnects above still work when
        # admin_user == application user.
        if role_exists:
            with engine.connect().execution_options(
                isolation_level="AUTOCOMMIT"
            ) as conn:
                lit = conn.execute(
                    text("SELECT quote_literal(:pw)"),
                    {"pw": password},
                ).scalar()
                conn.exec_driver_sql(
                    f"ALTER ROLE {role_sql} WITH LOGIN PASSWORD {lit}"
                )
                role_password_set = True

        # Verify app credentials work.
        app_dsn = build_hot_dsn(
            host=host,
            port=port_i,
            database=database,
            user=user,
            password=password,
            sslmode=sslmode,
        )
        verify = test_hot_connection(app_dsn)
        if not verify.get("ok"):
            raise HotStoreError(
                "Rôle/base créés mais la connexion applicative a échoué après alignement"
            )
        return {
            "ok": True,
            "admin_database": connected_db,
            "role_created": role_created,
            "role_password_set": role_password_set,
            "database_created": database_created,
            "database": database,
            "user": user,
            "ping_ms": verify.get("ping_ms"),
            "version": verify.get("version"),
        }
    except HotStoreError:
        raise
    except Exception as exc:
        raise HotStoreError(f"Provisionnement PostgreSQL échoué : {exc}") from exc
    finally:
        engine.dispose()


@dataclass
class HotStoreStatus:
    configured: bool
    enabled: bool
    host: str | None
    port: int | None
    database: str | None
    user: str | None
    sslmode: str | None
    password_set: bool
    engine_ready: bool
    ping_ms: float | None
    ping_error: str | None
    table_counts: dict[str, int]
    status_badge: str
    status_label: str
    last_migrate_at: str | None
    last_migrate_summary: str | None
    schema_prepared_at: str | None = None
    schema_prepared_by: str | None = None
    last_test_at: str | None = None
    last_test_ok: bool | None = None
    last_test_ms: float | None = None
    last_test_error: str | None = None
    migrate_skipped_at: str | None = None
    migrate_skipped_by: str | None = None
    wizard_steps: tuple[dict[str, Any], ...] = ()


def _iso(dt) -> str | None:
    if dt is None:
        return None
    try:
        return dt.isoformat()
    except Exception:
        return str(dt)


def build_hot_store_wizard_steps(
    *,
    configured: bool,
    last_test_ok: bool | None,
    schema_prepared: bool,
    migrate_done: bool,
    migrate_skipped: bool,
    enabled: bool,
) -> tuple[dict[str, Any], ...]:
    """Derive stepper states for the admin hot-store wizard."""
    tested = last_test_ok is True
    test_failed = last_test_ok is False
    migrate_ready = migrate_done or migrate_skipped

    def _step(
        sid: str,
        label: str,
        *,
        locked: bool,
        status: str,
        optional: bool = False,
    ) -> dict[str, Any]:
        return {
            "id": sid,
            "label": label,
            "locked": locked,
            "status": status,  # todo | done | failed | skipped | locked
            "optional": optional,
        }

    steps = [
        _step(
            "config",
            "Connexion",
            locked=False,
            status="done" if configured else "todo",
        ),
        _step(
            "test",
            "Test",
            locked=not configured,
            status=(
                "locked"
                if not configured
                else ("done" if tested else ("failed" if test_failed else "todo"))
            ),
        ),
        _step(
            "schema",
            "Schéma",
            locked=not tested,
            status=(
                "locked"
                if not tested
                else ("done" if schema_prepared else "todo")
            ),
        ),
        _step(
            "migrate",
            "Migration",
            locked=not schema_prepared,
            status=(
                "locked"
                if not schema_prepared
                else (
                    "done"
                    if migrate_done
                    else ("skipped" if migrate_skipped else "todo")
                )
            ),
            optional=True,
        ),
        _step(
            "enable",
            "Activation",
            locked=not (schema_prepared and migrate_ready),
            status=(
                "locked"
                if not (schema_prepared and migrate_ready)
                else ("done" if enabled else "todo")
            ),
        ),
    ]
    return tuple(steps)


def get_hot_store_status(config_db: Session, settings) -> HotStoreStatus:
    from app.portal_settings_service import get_portal_settings_row
    from app.secret_crypto import decrypt_secret

    row = get_portal_settings_row(config_db)
    if row is None:
        return HotStoreStatus(
            configured=False,
            enabled=False,
            host=None,
            port=None,
            database=None,
            user=None,
            sslmode=None,
            password_set=False,
            engine_ready=False,
            ping_ms=None,
            ping_error=None,
            table_counts={},
            status_badge="muted",
            status_label="Non configuré",
            last_migrate_at=None,
            last_migrate_summary=None,
            wizard_steps=build_hot_store_wizard_steps(
                configured=False,
                last_test_ok=None,
                schema_prepared=False,
                migrate_done=False,
                migrate_skipped=False,
                enabled=False,
            ),
        )

    host = (getattr(row, "hot_store_host", None) or "").strip() or None
    configured = bool(host)
    enabled = bool(getattr(row, "hot_store_enabled", False))
    password_set = bool(getattr(row, "hot_store_password_encrypted", None))
    last_at = getattr(row, "hot_store_last_migrate_at", None)
    last_summary = getattr(row, "hot_store_last_migrate_summary", None)
    schema_at = getattr(row, "hot_store_schema_prepared_at", None)
    schema_by = getattr(row, "hot_store_schema_prepared_by", None)
    last_test_at = getattr(row, "hot_store_last_test_at", None)
    last_test_ok = getattr(row, "hot_store_last_test_ok", None)
    last_test_ms = getattr(row, "hot_store_last_test_ms", None)
    last_test_error = getattr(row, "hot_store_last_test_error", None)
    migrate_skipped_at = getattr(row, "hot_store_migrate_skipped_at", None)
    migrate_skipped_by = getattr(row, "hot_store_migrate_skipped_by", None)

    ping_ms: float | None = None
    ping_error: str | None = None
    engine_ready = False
    counts: dict[str, int] = {}

    if configured:
        try:
            eng = sync_hot_engine_from_config(config_db, settings)
            if eng is not None:
                t0 = time.perf_counter()
                with eng.connect() as conn:
                    conn.execute(text("SELECT 1"))
                ping_ms = round((time.perf_counter() - t0) * 1000, 1)
                engine_ready = True
                if enabled:
                    for name in HOT_TABLE_NAMES:
                        try:
                            with eng.connect() as conn:
                                counts[name] = int(
                                    conn.execute(
                                        text(f'SELECT count(*) FROM "{name}"')
                                    ).scalar()
                                    or 0
                                )
                        except Exception:
                            counts[name] = -1
        except Exception as exc:
            ping_error = str(exc)[:300]
            engine_ready = False

    if not configured:
        badge, label = "muted", "Non configuré"
    elif ping_error:
        badge, label = "error", "Connexion en échec"
    elif enabled and engine_ready:
        badge, label = "ok", "Actif (Postgres)"
    elif engine_ready:
        badge, label = "warn", "Configuré (inactif)"
    else:
        badge, label = "warn", "Configuré"

    wizard_steps = build_hot_store_wizard_steps(
        configured=configured,
        last_test_ok=last_test_ok if last_test_ok is None else bool(last_test_ok),
        schema_prepared=bool(schema_at or last_at),
        migrate_done=bool(last_at),
        migrate_skipped=bool(migrate_skipped_at),
        enabled=enabled,
    )

    return HotStoreStatus(
        configured=configured,
        enabled=enabled,
        host=host,
        port=int(getattr(row, "hot_store_port", None) or 5432) if configured else None,
        database=(getattr(row, "hot_store_database", None) or None) if configured else None,
        user=(getattr(row, "hot_store_user", None) or None) if configured else None,
        sslmode=(getattr(row, "hot_store_sslmode", None) or "prefer") if configured else None,
        password_set=password_set,
        engine_ready=engine_ready,
        ping_ms=ping_ms,
        ping_error=ping_error,
        table_counts=counts,
        status_badge=badge,
        status_label=label,
        last_migrate_at=last_at.isoformat() if last_at else None,
        last_migrate_summary=last_summary,
        schema_prepared_at=_iso(schema_at),
        schema_prepared_by=(schema_by or None),
        last_test_at=_iso(last_test_at),
        last_test_ok=bool(last_test_ok) if last_test_ok is not None else None,
        last_test_ms=float(last_test_ms) if last_test_ms is not None else None,
        last_test_error=(last_test_error or None),
        migrate_skipped_at=_iso(migrate_skipped_at),
        migrate_skipped_by=(migrate_skipped_by or None),
        wizard_steps=wizard_steps,
    )


class RoutingSession(Session):
    """Session that routes hot-model operations to Postgres when enabled."""

    def get_bind(self, mapper=None, clause=None, bind=None, **kw):  # noqa: ANN001
        if mapper is not None:
            cls = getattr(mapper, "class_", None)
            if is_hot_model(cls) and hot_store_runtime_enabled():
                eng = get_cached_hot_engine()
                if eng is not None:
                    return eng
        return super().get_bind(mapper=mapper, clause=clause, bind=bind, **kw)


def make_session_factory(bind: Engine, **kwargs: Any):
    """sessionmaker using RoutingSession (hot routing when enabled)."""
    return sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=bind,
        class_=RoutingSession,
        **kwargs,
    )


def hot_table_columns(model: type) -> Sequence[str]:
    return tuple(c.name for c in model.__table__.columns)


def copy_table_rows(
    source: Session,
    dest_engine: Engine,
    model: type,
    *,
    batch_size: int = 500,
) -> int:
    """Copy all rows of ``model`` from source session into dest engine. Returns count."""
    from sqlalchemy.orm import sessionmaker as _sm

    DestSession = _sm(bind=dest_engine, autoflush=False, autocommit=False)
    dest = DestSession()
    copied = 0
    try:
        # Clear destination table first (full replace semantics for migrate).
        dest.query(model).delete()
        dest.commit()

        rows = source.query(model).yield_per(batch_size)
        batch: list[dict] = []
        cols = hot_table_columns(model)

        def _flush(items: list[dict]) -> None:
            nonlocal copied
            if not items:
                return
            dest.bulk_insert_mappings(model, items)
            dest.commit()
            copied += len(items)

        for row in rows:
            batch.append({name: getattr(row, name) for name in cols})
            if len(batch) >= batch_size:
                _flush(batch)
                batch = []
        _flush(batch)
        return copied
    except Exception:
        dest.rollback()
        raise
    finally:
        dest.close()


def migrate_all_hot_tables(
    config_db: Session,
    dest_engine: Engine,
    *,
    tables: Iterable[str] | None = None,
) -> dict[str, int]:
    """Copy hot tables from the config DB (SQLite) into Postgres."""
    wanted = set(tables) if tables is not None else set(HOT_TABLE_NAMES)
    results: dict[str, int] = {}
    prepare_hot_schema(dest_engine)
    for model in HOT_MODELS:
        if model.__tablename__ not in wanted:
            continue
        results[model.__tablename__] = copy_table_rows(config_db, dest_engine, model)
    return results
