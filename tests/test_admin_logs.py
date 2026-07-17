"""Admin /admin/logs viewer and request_id middleware tests."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import AuditLog
from app.web.log_masking import mask_secrets, mask_secrets_text

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}
USER_HEADERS = {
    "X-Email": "user@example.com",
    "X-Groups": "transfer-users",
}


def test_logs_rbac_forbidden_for_non_admin(client: TestClient):
    resp = client.get("/admin/logs", headers=USER_HEADERS)
    assert resp.status_code == 403


def test_logs_filter_by_action_and_actor(client: TestClient, db_session: Session):
    log_action(db_session, actor="alice@ex.com", action="realm.test", target="r1", details={"status": "ok"})
    log_action(db_session, actor="bob@ex.com", action="health.probe", target="app", details={"status": "warn"})
    log_action(
        db_session,
        actor="alice@ex.com",
        action="credential.set",
        target="transfer",
        details={"password": "SHOULD_NOT_APPEAR", "client_secret": "xyz"},
    )

    resp = client.get("/admin/logs?action=realm.test", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert resp.text.count("<tr>") >= 2  # header + at least one data row
    assert ">realm.test<" in resp.text or "<code>realm.test</code>" in resp.text
    # Filtered table should not list health.probe as a row action (dropdown may still list it)
    assert "<code>health.probe</code>" not in resp.text

    resp2 = client.get("/admin/logs?actor=alice", headers=ADMIN_HEADERS)
    assert resp2.status_code == 200
    assert "alice@ex.com" in resp2.text
    assert "<td" in resp2.text
    # bob should not appear in a data cell as actor for filtered results
    assert resp2.text.count("bob@ex.com") == 0


def test_logs_masks_sensitive_details(client: TestClient, db_session: Session):
    log_action(
        db_session,
        actor="admin@example.com",
        action="realm.create",
        target="demo",
        details={"client_secret": "super-secret-value", "password": "p@ss"},
    )
    resp = client.get("/admin/logs?action=realm.create", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "super-secret-value" not in resp.text
    assert "p@ss" not in resp.text
    assert "***" in resp.text


def test_logs_filter_by_date(client: TestClient, db_session: Session):
    entry = AuditLog(
        actor="admin@example.com",
        action="app.create",
        target="x",
        details={},
        created_at=datetime(2026, 1, 15, tzinfo=timezone.utc),
    )
    db_session.add(entry)
    db_session.commit()

    ok = client.get("/admin/logs?date_from=2026-01-01&date_to=2026-01-31", headers=ADMIN_HEADERS)
    assert ok.status_code == 200
    assert "<code>app.create</code>" in ok.text

    empty = client.get("/admin/logs?date_from=2026-06-01&date_to=2026-06-30", headers=ADMIN_HEADERS)
    assert empty.status_code == 200
    assert "<code>app.create</code>" not in empty.text


def test_mask_secrets_helpers():
    assert mask_secrets({"password": "x", "ok": True}) == {"password": "***", "ok": True}
    assert "secret=***" in mask_secrets_text("client_secret=abc123 rest")


def test_request_id_header_present_and_unique(client: TestClient):
    r1 = client.get("/api/health")
    r2 = client.get("/api/health")
    assert "x-request-id" in {k.lower() for k in r1.headers.keys()}
    id1 = r1.headers.get("x-request-id") or r1.headers.get("X-Request-Id")
    id2 = r2.headers.get("x-request-id") or r2.headers.get("X-Request-Id")
    assert id1
    assert id2
    assert id1 != id2


def test_request_id_propagates_incoming(client: TestClient):
    resp = client.get("/api/health", headers={"X-Request-Id": "fixed-correlation-id"})
    assert resp.headers.get("x-request-id") == "fixed-correlation-id"
