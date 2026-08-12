"""log_action event_code / severity wiring tests."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.audit import log_action
from app.audit.event_catalog import Severity
from app.models import AuditLog
from app.web.admin_logs_query import list_admin_log_entries, serialize_audit_row


def test_log_action_resolves_known_action(db_session: Session):
    entry = log_action(
        db_session,
        actor="admin@example.com",
        action="breakglass.login_failed",
        ip_address="10.0.0.1",
        forward_to_siem=False,
    )
    assert entry is not None
    assert entry.event_code == "BST-BGL-2001"
    assert entry.severity == Severity.WARNING.value


def test_log_action_uncatalogued(db_session: Session):
    entry = log_action(
        db_session,
        actor="admin@example.com",
        action="future.brand.new.action",
        forward_to_siem=False,
    )
    assert entry is not None
    assert entry.event_code.endswith("-0000")
    assert entry.severity == Severity.WARNING.value


def test_log_action_explicit_code(db_session: Session):
    entry = log_action(
        db_session,
        actor="admin@example.com",
        action="breakglass.login",
        code="BST-BGL-4001",
        details={"note": "simulated non-lan success"},
        forward_to_siem=False,
    )
    assert entry is not None
    assert entry.event_code == "BST-BGL-4001"
    assert entry.severity == Severity.CRITICAL.value


def test_historical_row_without_event_code(db_session: Session):
    row = AuditLog(
        actor="legacy",
        action="app.create",
        details=None,
        ip_address="127.0.0.1",
        event_code=None,
        severity=None,
    )
    db_session.add(row)
    db_session.commit()
    db_session.refresh(row)
    ser = serialize_audit_row(row)
    assert ser["historical"] is True
    assert ser["event_code"] is None
    assert ser["catalog_severity"] in {"NOTICE", "INFO", "ERROR"}


def test_severity_min_filter(db_session: Session):
    log_action(db_session, actor="a", action="admin.container_logs.viewed", forward_to_siem=False)
    log_action(db_session, actor="a", action="security.ban.applied", forward_to_siem=False)
    entries, total, _ = list_admin_log_entries(db_session, severity_min="WARNING", limit=100)
    assert total >= 1
    assert all(
        e["catalog_severity"] in {"WARNING", "ERROR", "CRITICAL"} for e in entries
    )
    assert any(e["action"] == "security.ban.applied" for e in entries)
    assert not any(e["action"] == "admin.container_logs.viewed" for e in entries)
