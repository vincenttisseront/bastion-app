"""SQLite/SQLCipher open/close serialization (incident 2026-11-06, process frozen).

sqlcipher3 is Linux-only: these tests drive the same code paths with stdlib
``sqlite3`` (same DBAPI shape, same ``factory=`` hook) and fake bases.
"""

from __future__ import annotations

import gc
import sqlite3
import threading
import time
import warnings
from typing import ClassVar

import pytest
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from app import db_cipher
from app.db_cipher import (
    connect_serialized,
    create_portal_engine,
    serialized_connection_class,
    sqlite_open_close_lock,
)
from app.sso_settings import Settings, get_settings


def _lock_owned() -> bool:
    return sqlite_open_close_lock()._is_owned()


@pytest.fixture
def plaintext_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.delenv("VAULT_PORTAL_DB_ENCRYPTION_KEY", raising=False)
    get_settings.cache_clear()
    yield Settings(vault_portal_db_encryption_key="")
    get_settings.cache_clear()


class _RecordingModule:
    """DBAPI module stand-in that records whether connect ran under the lock."""

    Connection = sqlite3.Connection

    def __init__(self) -> None:
        self.calls: list[tuple[bool, type]] = []

    def connect(self, *cargs, **cparams):
        self.calls.append((_lock_owned(), cparams["factory"]))
        return sqlite3.connect(*cargs, **cparams)


def test_connect_runs_under_lock_with_serialized_factory(tmp_path):
    module = _RecordingModule()
    conn = connect_serialized(module, str(tmp_path / "a.db"), check_same_thread=False)
    try:
        assert not _lock_owned()  # released once connect returns
        [(owned, factory)] = module.calls
        assert owned is True
        assert issubclass(factory, sqlite3.Connection)
        assert factory._bastion_serialized_close is True
        assert type(conn) is factory
        assert conn.execute("select 1").fetchone() == (1,)
    finally:
        conn.close()


def test_connect_wraps_caller_factory(tmp_path):
    class Custom(sqlite3.Connection):
        pass

    conn = connect_serialized(sqlite3, str(tmp_path / "b.db"), factory=Custom)
    try:
        assert isinstance(conn, Custom)
        assert type(conn)._bastion_serialized_close is True
    finally:
        conn.close()


def test_serialized_class_is_cached_and_idempotent():
    cls = serialized_connection_class(sqlite3.Connection)
    assert serialized_connection_class(sqlite3.Connection) is cls
    assert serialized_connection_class(cls) is cls


def test_close_runs_under_lock(tmp_path):
    seen: list[bool] = []

    class Probe(sqlite3.Connection):
        def close(self) -> None:
            seen.append(_lock_owned())
            super().close()

    conn = connect_serialized(sqlite3, str(tmp_path / "c.db"), factory=Probe)
    conn.close()
    assert seen == [True]


def test_gc_of_unclosed_stdlib_connection_closes_under_lock(tmp_path):
    seen: list[bool] = []

    class Probe(sqlite3.Connection):
        def __del__(self) -> None:  # runs as the "base finalizer" of the subclass
            seen.append(_lock_owned())
            base = getattr(super(), "__del__", None)
            if base is not None:
                base()

    conn = connect_serialized(sqlite3, str(tmp_path / "d.db"), factory=Probe)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ResourceWarning)
        del conn
        gc.collect()
    assert seen == [True]


class _FakeCipherConnection:
    """Base without ``__del__`` (like sqlcipher3's C type): close in dealloc."""

    closes: ClassVar[list[bool]] = []

    def close(self) -> None:
        _FakeCipherConnection.closes.append(_lock_owned())


def test_gc_without_base_finalizer_calls_close_under_lock():
    _FakeCipherConnection.closes = []
    cls = serialized_connection_class(_FakeCipherConnection)
    obj = cls()
    obj.close()
    del obj
    gc.collect()
    # explicit close + finalizer close, both under the lock
    assert _FakeCipherConnection.closes == [True, True]


def test_finalizer_swallows_close_errors():
    class Broken:
        def close(self) -> None:
            raise RuntimeError("boom")

    obj = serialized_connection_class(Broken)()
    del obj  # must not raise / print "Exception ignored in __del__"
    gc.collect()


def test_plaintext_engine_routes_connect_through_lock(tmp_path, monkeypatch, plaintext_settings):
    calls: list[str] = []
    real = db_cipher.connect_serialized

    def spy(module, *cargs, **cparams):
        calls.append(module.__name__)
        return real(module, *cargs, **cparams)

    monkeypatch.setattr(db_cipher, "connect_serialized", spy)
    engine = create_portal_engine(
        f"sqlite:///{(tmp_path / 'portal.db').as_posix()}", plaintext_settings
    )
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar() == "wal"
        dbapi_conn = conn.connection.dbapi_connection
        assert type(dbapi_conn)._bastion_serialized_close is True
        assert isinstance(dbapi_conn, sqlite3.Connection)
    assert len(calls) == 1 and calls[0].startswith("sqlite3")  # sqlite3.dbapi2
    engine.dispose()


def test_sqlcipher_engine_routes_connect_through_lock(tmp_path, monkeypatch):
    """Encrypted branch (module=sqlcipher3) also gets the lock — stdlib stands in."""
    monkeypatch.setenv("VAULT_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.delenv("VAULT_PORTAL_DB_ENCRYPTION_KEY", raising=False)
    get_settings.cache_clear()
    settings = Settings(vault_portal_db_encryption_key="ab" * 32)
    monkeypatch.setattr(db_cipher, "_import_sqlcipher", lambda: sqlite3)
    seen: list[str] = []
    real = db_cipher.connect_serialized

    def spy(module, *cargs, **cparams):
        seen.append(module.__name__)
        return real(module, *cargs, **cparams)

    monkeypatch.setattr(db_cipher, "connect_serialized", spy)
    try:
        engine = create_portal_engine(
            f"sqlite:///{(tmp_path / 'enc.db').as_posix()}", settings
        )
        with engine.connect() as conn:
            assert type(conn.connection.dbapi_connection)._bastion_serialized_close is True
        assert seen and all(name.startswith("sqlite3") for name in seen)
        engine.dispose()
    finally:
        get_settings.cache_clear()


class _Tracking(sqlite3.Connection):
    """Counts threads inside the C open/close; sleeps there to invite overlap."""

    guard = threading.Lock()
    active = 0
    max_active = 0
    opens = 0
    closes = 0

    @classmethod
    def _enter(cls) -> None:
        with cls.guard:
            cls.active += 1
            cls.max_active = max(cls.max_active, cls.active)

    @classmethod
    def _leave(cls, attr: str) -> None:
        with cls.guard:
            cls.active -= 1
            setattr(cls, attr, getattr(cls, attr) + 1)

    def __init__(self, *args, **kwargs) -> None:
        _Tracking._enter()
        try:
            super().__init__(*args, **kwargs)
            time.sleep(0.0005)  # releases the GIL: unserialized opens would overlap
        finally:
            _Tracking._leave("opens")

    def close(self) -> None:
        _Tracking._enter()
        try:
            time.sleep(0.0005)
            super().close()
        finally:
            _Tracking._leave("closes")


def test_concurrent_sessions_never_overlap_open_and_close(tmp_path, plaintext_settings):
    """Stress: many threads open/close NullPool sessions on one WAL file.

    Open and close must never run concurrently, and the run must finish (no
    self-deadlock between the lock, GC finalizers and SQLite).
    """
    _Tracking.active = _Tracking.max_active = _Tracking.opens = _Tracking.closes = 0
    db_path = tmp_path / "stress.db"
    engine = create_portal_engine(
        f"sqlite:///{db_path.as_posix()}",
        plaintext_settings,
        connect_args={"factory": _Tracking},
    )
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE t (x INTEGER)"))
    Session = sessionmaker(bind=engine)
    threads_n, iterations = 8, 40
    errors: list[BaseException] = []

    def worker(n: int) -> None:
        try:
            for i in range(iterations):
                with Session() as db:
                    db.execute(text("SELECT count(*) FROM t")).scalar()
                    if i % 10 == n % 10:
                        db.execute(text("INSERT INTO t VALUES (:x)"), {"x": i})
                        db.commit()
                if i % 7 == 0:
                    # GC path: an unclosed DBAPI connection, finalized by GC.
                    raw = connect_serialized(
                        sqlite3, str(db_path), factory=_Tracking, check_same_thread=False
                    )
                    raw.execute("SELECT 1").fetchone()
                    del raw
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def run_all() -> None:
        workers = [threading.Thread(target=worker, args=(n,)) for n in range(threads_n)]
        for t in workers:
            t.start()
        for t in workers:
            t.join()

    runner = threading.Thread(target=run_all, daemon=True)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ResourceWarning)
        runner.start()
        runner.join(timeout=120)
        gc.collect()
    assert not runner.is_alive(), "open/close stress did not finish (deadlock?)"
    assert errors == []
    assert _Tracking.max_active == 1
    assert _Tracking.opens >= threads_n * iterations
    engine.dispose()
