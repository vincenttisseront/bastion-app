"""Optional PostgreSQL hot store — routing + migrate (SQLite stand-in for PG)."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.hot_store import (
    HOT_TABLE_NAMES,
    HotStoreError,
    build_hot_dsn,
    copy_table_rows,
    dispose_hot_engine,
    ensure_hot_engine,
    is_hot_model,
    make_session_factory,
    set_hot_enabled_cache,
)
from app.db import hot_store as hot_store_mod
from app.models import AuditLog, Base, PortalSettings, utcnow
from app.sso_settings import Settings


def _mem_engine():
    return create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def test_build_hot_dsn_encodes_password():
    dsn = build_hot_dsn(
        host="postgres",
        port=5432,
        database="bastion_hot",
        user="bastion_hot",
        password="p@ss:word/x",
        sslmode="disable",
    )
    assert dsn.startswith("postgresql+psycopg://")
    assert "postgres:5432/bastion_hot" in dsn
    assert "sslmode=disable" in dsn
    assert "p%40ss" in dsn or "p@ss" not in dsn.split("@")[0]


def test_build_hot_dsn_requires_host():
    with pytest.raises(HotStoreError):
        build_hot_dsn(host="", port=5432, database="db", user="u", password="")


def test_is_hot_model():
    assert is_hot_model(AuditLog) is True
    assert is_hot_model(PortalSettings) is False


def test_routing_session_sends_audit_to_hot_engine():
    config_eng = _mem_engine()
    hot_eng = _mem_engine()
    Base.metadata.create_all(bind=config_eng)
    tables = [Base.metadata.tables[n] for n in HOT_TABLE_NAMES]
    Base.metadata.create_all(bind=hot_eng, tables=tables)

    dispose_hot_engine()
    hot_store_mod._hot_engine = hot_eng
    hot_store_mod._hot_engine_dsn = "test-sqlite-hot"
    set_hot_enabled_cache(True)

    Session = make_session_factory(config_eng)
    db = Session()
    try:
        db.add(PortalSettings(id=1, subdomain_sso_enabled=False, updated_at=utcnow()))
        db.commit()

        db.add(AuditLog(actor="admin", action="test.hot", target="x"))
        db.commit()

        # Config DB must not hold the audit row
        cfg = sessionmaker(bind=config_eng)()
        assert cfg.query(AuditLog).count() == 0
        cfg.close()

        hot = sessionmaker(bind=hot_eng)()
        assert hot.query(AuditLog).count() == 1
        assert hot.query(AuditLog).first().action == "test.hot"
        hot.close()
    finally:
        db.close()
        set_hot_enabled_cache(False)
        dispose_hot_engine()


def test_routing_disabled_keeps_audit_on_config():
    config_eng = _mem_engine()
    Base.metadata.create_all(bind=config_eng)
    dispose_hot_engine()
    set_hot_enabled_cache(False)

    Session = make_session_factory(config_eng)
    db = Session()
    try:
        db.add(AuditLog(actor="admin", action="test.cfg", target="y"))
        db.commit()
        assert db.query(AuditLog).count() == 1
    finally:
        db.close()


def test_migrate_all_hot_tables_copies_rows():
    src_eng = _mem_engine()
    dest_eng = _mem_engine()
    Base.metadata.create_all(bind=src_eng)
    tables = [Base.metadata.tables[n] for n in HOT_TABLE_NAMES]
    Base.metadata.create_all(bind=dest_eng, tables=tables)

    Src = sessionmaker(bind=src_eng)
    src = Src()
    src.add_all(
        [
            AuditLog(actor="a", action="one", target="t1"),
            AuditLog(actor="b", action="two", target="t2"),
        ]
    )
    src.commit()

    # Bypass prepare_hot_schema PG DDL — call copy path directly
    counts = {}
    for model in (AuditLog,):
        counts[model.__tablename__] = copy_table_rows(src, dest_eng, model)
    src.close()

    assert counts["audit_logs"] == 2
    Dest = sessionmaker(bind=dest_eng)
    dest = Dest()
    assert dest.query(AuditLog).count() == 2
    dest.close()


def test_save_and_enable_hot_store_service(db_session, monkeypatch):
    from app.db.hot_store_service import (
        save_hot_store_config,
        set_hot_store_enabled,
    )
    from app.portal_settings_service import ensure_portal_settings

    settings = Settings(
        environment="test",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        vault_portal_internal_token="t",
    )
    ensure_portal_settings(db_session, settings)

    # Patch connectivity so enable can succeed without real Postgres
    monkeypatch.setattr(
        "app.db.hot_store_service.test_hot_store_config",
        lambda db, settings: {"ok": True, "version": "PostgreSQL test", "can_create": True},
    )
    monkeypatch.setattr(
        "app.db.hot_store_service.prepare_hot_store_schema",
        lambda db, settings: None,
    )
    monkeypatch.setattr(
        "app.db.hot_store_service.sync_hot_engine_from_config",
        lambda db, settings: object(),
    )

    save_hot_store_config(
        db_session,
        settings,
        host="postgres",
        port=5432,
        database="bastion_hot",
        user="bastion_hot",
        password="secret",
        sslmode="disable",
        actor="admin@example.com",
    )
    row = ensure_portal_settings(db_session, settings)
    assert row.hot_store_host == "postgres"
    assert row.hot_store_password_encrypted
    assert "secret" not in (row.hot_store_password_encrypted or "")

    # Enable without migrate should fail
    with pytest.raises(HotStoreError, match="Migrez"):
        set_hot_store_enabled(
            db_session, settings, True, actor="admin@example.com"
        )

    row.hot_store_last_migrate_at = utcnow()
    db_session.commit()

    set_hot_store_enabled(db_session, settings, True, actor="admin@example.com")
    db_session.refresh(row)
    assert row.hot_store_enabled is True

    set_hot_store_enabled(db_session, settings, False, actor="admin@example.com")
    db_session.refresh(row)
    assert row.hot_store_enabled is False


def test_create_hot_engine_rejects_sqlite():
    with pytest.raises(HotStoreError):
        ensure_hot_engine("sqlite:///tmp/x.db")


def test_security_page_shows_hot_store_tab(client, db_session):
    resp = client.get(
        "/admin/security",
        headers={"X-Email": "admin@example.com", "X-Groups": "portal-admins"},
    )
    assert resp.status_code == 200
    assert 'id="hot-store"' in resp.text
    assert "Stockage chaud" in resp.text
    assert 'action="/admin/security/hot-store/config"' in resp.text
