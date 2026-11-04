"""Regression tests — review findings A1 (sync SQL on the event loop + no WAL),
A2 (unbounded upload processed on the loop) and S6 (ban check fails open)."""

from __future__ import annotations

import asyncio
import io
import sqlite3
import threading
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException, UploadFile
from fastapi.testclient import TestClient
from sqlalchemy import text
from starlette.requests import Request

from app.sso_settings import Settings

MAIN = threading.main_thread()


def _settings(**extra) -> Settings:
    base = dict(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
        environment="test",
    )
    base.update(extra)
    return Settings(**base)


def _request(headers: dict[str, str] | None = None, path: str = "/") -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "query_string": b"",
            "headers": raw,
            "client": ("10.0.0.8", 1234),
            "server": ("portal.test", 443),
            "scheme": "https",
        }
    )


class _ThreadProbe:
    """Callable recording the thread it ran on, returning ``result``."""

    def __init__(self, result=None):
        self.result = result
        self.threads: list[threading.Thread] = []

    def __call__(self, *_a, **_k):
        self.threads.append(threading.current_thread())
        return self.result

    @property
    def off_loop(self) -> bool:
        return bool(self.threads) and all(t is not MAIN for t in self.threads)


# --- A1 : WAL + busy_timeout --------------------------------------------------


def test_a1_sqlite_engine_uses_wal(tmp_path):
    from app.db_cipher import create_portal_engine

    url = f"sqlite:///{tmp_path / 'portal.db'}"
    engine = create_portal_engine(url, _settings(database_url=url))
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar().lower() == "wal"
        assert conn.execute(text("PRAGMA busy_timeout")).scalar() == 5000
        assert conn.execute(text("PRAGMA synchronous")).scalar() == 1  # NORMAL
    engine.dispose()


def test_a1_file_backup_keeps_uncheckpointed_wal_pages(tmp_path):
    """With WAL, copying only portal.db would drop committed rows."""
    from app.db_cipher import copy_sqlite_file, create_portal_engine

    db_path = tmp_path / "portal.db"
    url = f"sqlite:///{db_path}"
    engine = create_portal_engine(url, _settings(database_url=url))
    holder = engine.connect()  # keeps the WAL from being checkpointed on close
    holder.execute(text("PRAGMA wal_autocheckpoint=0"))
    holder.execute(text("CREATE TABLE t (v TEXT)"))
    holder.execute(text("INSERT INTO t VALUES ('committed')"))
    holder.commit()
    assert (tmp_path / "portal.db-wal").stat().st_size > 0

    dest = tmp_path / "backup.db"
    copy_sqlite_file(db_path, dest)
    holder.close()
    engine.dispose()

    conn = sqlite3.connect(dest)
    try:
        assert conn.execute("SELECT v FROM t").fetchall() == [("committed",)]
    finally:
        conn.close()


# --- A1 : auth paths run their SQL off the event loop ------------------------


def test_a1_subdomain_auth_sql_off_loop(db_session):
    from app.subdomain import subdomain_auth as mod

    probe = _ThreadProbe(result=None)  # no app → 401 deny path
    with (
        patch.object(mod, "_resolve_app_by_host", probe),
        patch.object(mod, "_deny_no_app", lambda *a, **k: mod.Response(status_code=401)),
    ):
        resp = asyncio.run(
            mod.subdomain_auth(
                _request({"X-Original-Host": "x.example.test"}),
                db=db_session,
                settings=_settings(),
            )
        )
    assert resp.status_code == 401
    assert probe.off_loop


def test_a1_activesync_auth_sql_off_loop(db_session):
    from app.subdomain import activesync_auth as mod

    probe = _ThreadProbe(result=None)
    with (
        patch.object(mod, "_resolve_app_by_host", probe),
        patch.object(mod, "_log_activesync", lambda *a, **k: None),
    ):
        resp = asyncio.run(
            mod.activesync_auth(
                _request({"X-Original-Host": "mail.example.test"}),
                db=db_session,
                settings=_settings(),
            )
        )
    assert resp.status_code == 401
    assert probe.off_loop


def test_a1_portal_auth_request_sql_off_loop(db_session):
    from app.auth import auth_request as mod

    native = _ThreadProbe(result=None)
    target = _ThreadProbe(result=None)  # no IdP configured
    with (
        patch.object(mod, "_native_oidc_auth_response", native),
        patch.object(mod, "_oauth2_proxy_target", target),
    ):
        resp = asyncio.run(mod.oauth2_auth(_request(), settings=_settings(), db=db_session))
    assert resp.status_code == 401
    assert native.off_loop and target.off_loop


def test_a1_require_user_enriched_resolves_identity_off_loop():
    from app.web import user_context as mod

    user = mod.UserContext(
        email="u@example.com",
        username="u",
        groups=[],
        realm_slug="default",
        auth_source="sso",
        is_admin=False,
    )
    probe = _ThreadProbe(result=user)
    with patch.object(mod, "require_user", probe):
        got = asyncio.run(mod.require_user_enriched(_request(), db=MagicMock(), settings=_settings()))
    assert got is user
    assert probe.off_loop


def test_a1_ban_middleware_check_off_loop():
    from app.security.banning import middleware as mod

    probe = _ThreadProbe(result=(True, "", None))
    with (
        patch.object(mod, "check_request_allowed", probe),
        patch.object(mod, "SessionLocal", MagicMock()),
    ):
        outcome = asyncio.run(
            mod.run_in_threadpool(
                mod._pre_check, ip="203.0.113.9", path="/auth/login", method="POST", username=""
            )
        )
        mod.end_concurrent("203.0.113.9")
    assert outcome is True
    assert probe.off_loop


# --- S6 : fail closed on login when the ban check itself fails ---------------


def _failing_check(*_a, **_k):
    raise RuntimeError("database is locked")


@pytest.mark.parametrize("path", ["/auth/login", "/auth/breakglass"])
def test_s6_login_fails_closed_when_ban_check_errors(path):
    from app.security.banning import middleware as mod

    with (
        patch.object(mod, "check_request_allowed", _failing_check),
        patch.object(mod, "SessionLocal", MagicMock()),
        patch.object(mod, "is_login_path", lambda p, m: True),
    ):
        outcome = mod._pre_check(ip="203.0.113.9", path=path, method="POST", username="")
    assert getattr(outcome, "status_code", None) == 503
    assert outcome.headers.get("Retry-After") == "5"


def test_s6_login_path_detection_matches_real_endpoints():
    from app.security.banning.engine import is_login_path

    assert is_login_path("/auth/login", "POST")
    assert not is_login_path("/apps", "GET")


def test_s6_non_login_sensitive_path_stays_available_on_check_error():
    from app.security.banning import middleware as mod

    with (
        patch.object(mod, "check_request_allowed", _failing_check),
        patch.object(mod, "SessionLocal", MagicMock()),
    ):
        outcome = mod._pre_check(ip="203.0.113.9", path="/apps", method="GET", username="")
    assert outcome is False  # passes through, not tracked


# --- A2 : bounded upload, processed off the loop ------------------------------


def test_a2_read_upload_bounded_rejects_oversize():
    from app.files.upload_limits import read_upload_bounded

    small = UploadFile(file=io.BytesIO(b"x" * 10), filename="a.bin")
    assert asyncio.run(read_upload_bounded(small, max_bytes=10)) == b"x" * 10
    big = UploadFile(file=io.BytesIO(b"x" * 11), filename="b.bin")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(read_upload_bounded(big, max_bytes=10))
    assert exc.value.status_code == 413


ADMIN_HEADERS = {"X-Email": "admin@example.com", "X-Groups": "portal-admins"}


def test_a2_portal_upload_over_limit_returns_413(client: TestClient, monkeypatch, tmp_path):
    from app.files.upload_limits import MAX_UPLOAD_BYTES
    from app.sso_settings import get_settings

    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    resp = client.post(
        "/files/upload",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        data={},
        files={"upload": ("big.bin", b"\0" * (MAX_UPLOAD_BYTES + 1), "application/octet-stream")},
    )
    assert resp.status_code == 413


def test_a2_portal_upload_processing_off_loop(client: TestClient, monkeypatch, tmp_path):
    from app.files import routes as mod
    from app.sso_settings import get_settings

    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    real = mod.deposit_file
    threads: list[threading.Thread] = []

    def spy(*a, **k):
        threads.append(threading.current_thread())
        return real(*a, **k)

    loop_threads: list[threading.Thread] = []
    real_read = mod.read_upload_bounded

    async def read_spy(upload):
        loop_threads.append(threading.current_thread())
        return await real_read(upload)

    monkeypatch.setattr(mod, "deposit_file", spy)
    monkeypatch.setattr(mod, "read_upload_bounded", read_spy)
    resp = client.post(
        "/files/upload",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        data={},
        files={"upload": ("ok.zip", b"payload", "application/zip")},
    )
    assert resp.status_code == 200, resp.text
    assert threads and loop_threads
    assert threads[0] is not loop_threads[0]  # deposit ran outside the loop thread
