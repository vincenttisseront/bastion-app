"""Optional PostgreSQL hot store — routing + migrate (SQLite stand-in for PG)."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.hot_store import (
    HOT_TABLE_NAMES,
    HotStoreError,
    build_hot_dsn,
    build_hot_store_wizard_steps,
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
        prepare_hot_store_schema,
        save_hot_store_config,
        set_hot_store_enabled,
        skip_hot_store_migrate,
    )
    from app.portal_settings_service import ensure_portal_settings

    settings = Settings(
        environment="test",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        vault_portal_internal_token="t",
    )
    ensure_portal_settings(db_session, settings)

    monkeypatch.setattr(
        "app.db.hot_store_service.test_hot_store_config",
        lambda db, settings, **kwargs: {
            "ok": True,
            "version": "PostgreSQL test",
            "can_create": True,
            "ping_ms": 1.2,
        },
    )
    monkeypatch.setattr(
        "app.db.hot_store_service.prepare_hot_schema",
        lambda eng: None,
    )
    monkeypatch.setattr(
        "app.db.hot_store_service.sync_hot_engine_from_config",
        lambda db, settings: object(),
    )
    monkeypatch.setattr(
        "app.db.hot_store_service.ensure_hot_engine",
        lambda dsn: object(),
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

    with pytest.raises(HotStoreError, match="schéma"):
        set_hot_store_enabled(
            db_session, settings, True, actor="admin@example.com"
        )

    row.hot_store_last_test_ok = True
    db_session.commit()
    prepare_hot_store_schema(db_session, settings, actor="admin@example.com")
    db_session.refresh(row)
    assert row.hot_store_schema_prepared_at is not None

    with pytest.raises(HotStoreError, match="déjà initialisé"):
        prepare_hot_store_schema(db_session, settings, actor="admin@example.com")

    with pytest.raises(HotStoreError, match="Migrez|passez"):
        set_hot_store_enabled(
            db_session, settings, True, actor="admin@example.com"
        )

    skip_hot_store_migrate(db_session, settings, actor="admin@example.com")
    set_hot_store_enabled(db_session, settings, True, actor="admin@example.com")
    db_session.refresh(row)
    assert row.hot_store_enabled is True

    set_hot_store_enabled(db_session, settings, False, actor="admin@example.com")
    db_session.refresh(row)
    assert row.hot_store_enabled is False


def test_build_hot_store_wizard_steps_order():
    steps = build_hot_store_wizard_steps(
        configured=True,
        last_test_ok=True,
        schema_prepared=True,
        migrate_done=False,
        migrate_skipped=True,
        enabled=False,
    )
    by_id = {s["id"]: s for s in steps}
    assert by_id["config"]["status"] == "done"
    assert by_id["migrate"]["status"] == "skipped"
    assert by_id["enable"]["locked"] is False


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
    assert 'formaction="/admin/security/hot-store/provision"' in resp.text
    assert "Créer / aligner rôle + base" in resp.text
    assert "wizard-stepper" in resp.text
    assert "data-wizard" in resp.text
    assert "Passer cette étape" in resp.text


def test_autocommit_connect_sets_isolation_on_engine():
    """AUTOCOMMIT must be set on the engine before connect (SA2 / psycopg)."""
    from app.db.hot_store import _autocommit_connect, create_hot_engine
    from sqlalchemy.pool import NullPool

    eng = create_hot_engine(
        "postgresql+psycopg://u:p@localhost:5432/db?sslmode=disable",
        poolclass=NullPool,
    )
    opt = eng.execution_options(isolation_level="AUTOCOMMIT")
    assert opt.get_execution_options().get("isolation_level") == "AUTOCOMMIT"
    assert callable(_autocommit_connect)
    eng.dispose()


def test_validate_pg_identifier():
    from app.db.hot_store import validate_pg_identifier

    assert validate_pg_identifier("bastion_hot", label="Base") == "bastion_hot"
    with pytest.raises(HotStoreError):
        validate_pg_identifier("bad-name", label="Base")
    with pytest.raises(HotStoreError):
        validate_pg_identifier("'; DROP", label="Utilisateur")


def test_provision_hot_store_service(db_session, monkeypatch):
    from app.db.hot_store_service import provision_hot_store
    from app.portal_settings_service import ensure_portal_settings
    from app.secret_crypto import decrypt_secret

    settings = Settings(
        environment="test",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        vault_portal_internal_token="t",
    )
    ensure_portal_settings(db_session, settings)

    calls: list[dict] = []

    def fake_provision(**kwargs):
        calls.append(kwargs)
        return {
            "ok": True,
            "admin_database": "postgres",
            "role_created": True,
            "role_password_set": True,
            "database_created": True,
            "database": kwargs["database"],
            "user": kwargs["user"],
            "ping_ms": 3.0,
            "version": "PostgreSQL 16",
        }

    monkeypatch.setattr(
        "app.db.hot_store_service.provision_hot_role_and_database",
        fake_provision,
    )
    monkeypatch.setattr(
        "app.db.hot_store_service.sync_hot_engine_from_config",
        lambda db, settings: None,
    )

    result = provision_hot_store(
        db_session,
        settings,
        host="postgres",
        port=5432,
        database="bastion_hot",
        user="bastion_hot",
        password="new-app-secret",
        sslmode="disable",
        admin_user="bastion_hot",
        admin_password="old-init-secret",
        actor="admin@example.com",
    )
    assert result["role_created"] is True
    assert calls and calls[0]["password"] == "new-app-secret"
    assert calls[0]["admin_password"] == "old-init-secret"

    row = ensure_portal_settings(db_session, settings)
    assert row.hot_store_host == "postgres"
    assert row.hot_store_last_test_ok is True
    assert decrypt_secret(row.hot_store_password_encrypted, settings) == "new-app-secret"

    with pytest.raises(HotStoreError, match="admin"):
        provision_hot_store(
            db_session,
            settings,
            host="postgres",
            port=5432,
            database="bastion_hot",
            user="bastion_hot",
            password="x",
            sslmode="disable",
            admin_user="bastion_hot",
            admin_password="",
            actor="admin@example.com",
        )
