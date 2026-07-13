"""Schema fix script and Alembic baseline tests."""

import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base


def _legacy_audit_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE audit_logs (
            id INTEGER PRIMARY KEY,
            actor_email TEXT,
            actor_username TEXT,
            action TEXT,
            entity_type TEXT,
            client_ip TEXT,
            created_at TEXT
        )
        """
    )
    conn.execute(
        """
        INSERT INTO audit_logs (actor_username, action, entity_type, client_ip, created_at)
        VALUES ('vincent', 'breakglass.login_failed', 'auth', '192.168.2.172', '2026-07-13')
        """
    )
    conn.commit()
    conn.close()


def test_fix_audit_logs_schema_script(tmp_path, monkeypatch):
    db_path = tmp_path / "portal.db"
    _legacy_audit_db(db_path)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")

    from app.sso_settings import get_settings
    from scripts.fix_audit_logs_schema import main

    get_settings.cache_clear()
    assert main() == 0

    conn = sqlite3.connect(db_path)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(audit_logs)")}
    assert "actor" in cols
    assert "ip_address" in cols
    row = conn.execute("SELECT actor, ip_address FROM audit_logs WHERE id=1").fetchone()
    assert row == ("vincent", "192.168.2.172")
    conn.close()


def test_alembic_baseline_on_legacy_audit_db(tmp_path, monkeypatch):
    db_path = tmp_path / "portal.db"
    _legacy_audit_db(db_path)
    db_url = f"sqlite:///{db_path.as_posix()}"
    monkeypatch.setenv("DATABASE_URL", db_url)

    from app.sso_settings import get_settings

    get_settings.cache_clear()

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    conn = sqlite3.connect(db_path)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(audit_logs)")}
    assert "actor" in cols
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert "breakglass_accounts" in tables
    conn.close()

    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)


def _legacy_realm_configs_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE realm_configs (
            id INTEGER PRIMARY KEY,
            slug TEXT NOT NULL UNIQUE,
            keycloak_realm TEXT NOT NULL,
            keycloak_base_url TEXT NOT NULL,
            client_id TEXT NOT NULL,
            oauth2_proxy_port INTEGER NOT NULL,
            oauth2_proxy_url TEXT NOT NULL,
            name TEXT,
            issuer_url TEXT,
            client_secret_encrypted TEXT,
            redirect_uri TEXT,
            scopes TEXT,
            is_default INTEGER,
            enabled INTEGER,
            created_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def test_alembic_drops_legacy_realm_columns(tmp_path, monkeypatch):
    db_path = tmp_path / "portal.db"
    _legacy_realm_configs_db(db_path)
    db_url = f"sqlite:///{db_path.as_posix()}"
    monkeypatch.setenv("DATABASE_URL", db_url)

    from app.sso_settings import get_settings

    get_settings.cache_clear()

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    conn = sqlite3.connect(db_path)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(realm_configs)")}
    assert "keycloak_realm" not in cols
    assert "keycloak_base_url" not in cols
    assert "oauth2_proxy_url" not in cols
    conn.execute(
        """
        INSERT INTO realm_configs (
            slug, name, issuer_url, client_id, client_secret_encrypted,
            redirect_uri, scopes, oauth2_proxy_port, is_default, enabled
        ) VALUES (
            'test', 'Test', 'https://idp.example/realms/test', 'client',
            'enc', 'https://portal.example/cb', 'openid', 4181, 0, 0
        )
        """
    )
    conn.commit()
    conn.close()
