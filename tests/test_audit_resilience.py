"""Audit logging resilience tests."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.audit import log_action
from app.breakglass_store import set_breakglass_password
from app.models import AuditLog, Base


def test_log_action_swallows_db_errors(db_session: Session):
    with patch.object(db_session, "commit", side_effect=SQLAlchemyError("boom")):
        result = log_action(
            db_session,
            actor="tester",
            action="unit.test",
            ip_address="127.0.0.1",
        )
    assert result is None


def test_login_failed_with_legacy_audit_schema(client: TestClient, db_session: Session):
    """Reproduces prod incident: legacy audit_logs without actor column."""
    db_session.execute(text("DROP TABLE IF EXISTS audit_logs"))
    db_session.execute(
        text(
            """
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY,
                actor_username TEXT,
                action TEXT,
                client_ip TEXT,
                created_at TEXT
            )
            """
        )
    )
    db_session.commit()
    set_breakglass_password(db_session, "admin", "correct-password-12")

    response = client.post(
        "/auth/breakglass",
        data={"username": "admin", "password": "wrong-password"},
        headers={"X-Real-IP": "10.0.0.8"},
    )

    assert response.status_code == 200
    assert "Identifiants invalides" in response.text
    assert "Service temporairement indisponible" not in response.text


def test_login_failed_audit_details_enriched(client: TestClient, db_session: Session):
    """breakglass.login_failed rows must never be empty {} — reason + via + UA.

    unknown_username + python-httpx UA = scan/probe (e.g. the active staging
    security tests); bad_password on a real account = typo or real attempt.
    """
    set_breakglass_password(db_session, "admin", "correct-password-12")

    resp = client.post(
        "/auth/breakglass",
        data={"username": "audit-probe-nonexistent", "password": "wrong"},
        headers={"X-Real-IP": "10.0.0.8", "User-Agent": "python-httpx/0.27"},
    )
    assert resp.status_code == 200
    row = (
        db_session.query(AuditLog)
        .filter_by(action="breakglass.login_failed")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert row is not None
    assert row.details["via"] == "form"
    assert row.details["reason"] == "unknown_username"
    assert "httpx" in row.details["user_agent"]

    resp = client.post(
        "/auth/breakglass",
        data={"username": "admin", "password": "wrong-password"},
        headers={"X-Real-IP": "10.0.0.8"},
    )
    assert resp.status_code == 200
    row = (
        db_session.query(AuditLog)
        .filter_by(action="breakglass.login_failed")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert row.details["reason"] == "bad_password"


def test_login_success_with_valid_breakglass(client: TestClient, db_session: Session):
    password = "correct-password-12"
    set_breakglass_password(db_session, "admin", password)

    response = client.post(
        "/auth/breakglass",
        data={"username": "admin", "password": password, "rd": "/dashboard"},
        headers={"X-Real-IP": "10.0.0.8"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == "/dashboard"
    assert "bg_session" in response.cookies
