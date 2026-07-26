"""Admin logs Live SSE + Docker containers whitelist tests."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.audit import log_action
from app.web.container_logs_settings import (
    add_allowed_container,
    update_container_logs_settings,
)
from app.web.docker_logs import _demux_frames

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _enable_containers(db: Session, *names: str, proxy: str = "http://docker-proxy.test:2375"):
    update_container_logs_settings(
        db,
        enabled=True,
        proxy_url=proxy,
        actor="admin@example.com",
    )
    for name in names:
        add_allowed_container(db, name, actor="admin@example.com")


def test_logs_page_unchanged_when_live_off(client: TestClient, db_session: Session):
    log_action(db_session, actor="alice@ex.com", action="realm.test", details={"status": "ok"})
    resp = client.get("/admin/logs?action=realm.test", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert 'id="audit-live-btn"' in resp.text
    assert 'aria-pressed="false"' in resp.text
    assert "<code>realm.test</code>" in resp.text
    assert 'id="tab-containers"' in resp.text


def test_audit_sse_pushes_new_entry(client: TestClient, db_engine, monkeypatch):
    import threading
    import time as time_mod
    from sqlalchemy.orm import sessionmaker

    monkeypatch.setenv("ADMIN_LOGS_SSE_TIMEOUT_SECONDS", "12")
    from app.sso_settings import get_settings

    get_settings.cache_clear()
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
    monkeypatch.setattr("app.web.admin_logs.SessionLocal", session_factory)

    db = session_factory()
    try:
        log_action(db, actor="admin@example.com", action="health.probe", details={})
    finally:
        db.close()

    ready = threading.Event()

    def _insert_later():
        ready.wait(timeout=5)
        time_mod.sleep(0.3)
        db2 = session_factory()
        try:
            log_action(
                db2,
                actor="alice@ex.com",
                action="realm.test",
                details={"status": "ok", "note": "live"},
            )
        finally:
            db2.close()

    threading.Thread(target=_insert_later, daemon=True).start()

    with client.stream(
        "GET",
        "/admin/logs/stream?action=realm.test",
        headers=ADMIN_HEADERS,
    ) as resp:
        assert resp.status_code == 200
        assert "text/event-stream" in (resp.headers.get("content-type") or "")
        ready.set()
        found = False
        deadline = time_mod.time() + 10
        for line in resp.iter_lines():
            if time_mod.time() > deadline:
                break
            if not line.startswith("data: "):
                continue
            payload = json.loads(line[6:])
            if (
                payload.get("action") == "realm.test"
                and payload.get("actor") == "alice@ex.com"
            ):
                found = True
                break
        assert found

    get_settings.cache_clear()


def test_container_whitelist_403_and_absent_from_selector(
    client: TestClient, db_session: Session
):
    _enable_containers(db_session, "bastion-app", "nginx")

    page = client.get("/admin/logs", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    assert 'value="bastion-app"' in page.text
    assert 'value="secret-db"' not in page.text

    denied = client.get(
        "/admin/logs/containers/secret-db/logs",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert denied.status_code == 403
    assert denied.json().get("detail") == "Forbidden"


def test_container_snapshot_audits_and_returns_text(client: TestClient, db_session: Session):
    _enable_containers(db_session, "bastion-app")

    async def fake_snapshot(cfg, container, *, tail=None):
        assert container == "bastion-app"
        return "hello from container\n"

    with patch(
        "app.web.admin_logs.fetch_container_log_snapshot",
        new=AsyncMock(side_effect=fake_snapshot),
    ):
        resp = client.get(
            "/admin/logs/containers/bastion-app/logs",
            headers=ADMIN_HEADERS,
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["container"] == "bastion-app"
    assert "hello from container" in body["text"]

    logs_page = client.get(
        "/admin/logs?action=admin.container_logs.viewed",
        headers=ADMIN_HEADERS,
    )
    assert logs_page.status_code == 200
    assert "admin.container_logs.viewed" in logs_page.text


def test_demux_frames_splits_multiplexed_payload():
    p1 = b"line1\n"
    p2 = b"line2\n"
    raw = (
        bytes([1, 0, 0, 0])
        + len(p1).to_bytes(4, "big")
        + p1
        + bytes([2, 0, 0, 0])
        + len(p2).to_bytes(4, "big")
        + p2
    )
    chunks, leftover = _demux_frames(bytearray(raw))
    assert chunks == ["line1\n", "line2\n"]
    assert leftover == bytearray()


def test_no_docker_sock_in_main_compose():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    main = (root / "docker-compose.yml").read_text(encoding="utf-8")
    assert "/var/run/docker.sock" not in main
    overlay = (root / "docker-compose.docker-logs.yml").read_text(encoding="utf-8")
    assert "docker-socket-proxy" in overlay
    assert "/var/run/docker.sock:/var/run/docker.sock:ro" in overlay
    assert "bastion-app must NEVER mount" in overlay or "NEVER mount" in overlay
