"""F-06: API break-glass login LAN gate (app defense-in-depth + nginx config)."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.breakglass_store import set_breakglass_password


def test_api_breakglass_login_rejected_from_public_ip(
    client: TestClient, db_session: Session
):
    set_breakglass_password(db_session, "admin", "super-secret-password")
    resp = client.post(
        "/api/admin/breakglass/login",
        json={"username": "admin", "password": "super-secret-password"},
        headers={"X-Real-IP": "203.0.113.10", "Accept": "application/json"},
    )
    assert resp.status_code == 403
    assert "bg_session" not in resp.cookies


def test_api_breakglass_login_ok_from_rfc1918(
    client: TestClient, db_session: Session
):
    set_breakglass_password(db_session, "admin", "super-secret-password")
    resp = client.post(
        "/api/admin/breakglass/login",
        json={"username": "admin", "password": "super-secret-password"},
        headers={"X-Real-IP": "10.0.0.50", "Accept": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.json().get("status") == "ok"
    assert "bg_session" in resp.cookies


def test_other_api_admin_still_requires_auth(client: TestClient):
    """Non-regression: sessions list stays behind require_admin (not LAN-public)."""
    resp = client.get(
        "/api/admin/breakglass/sessions",
        headers={"X-Real-IP": "10.0.0.50", "Accept": "application/json"},
    )
    assert resp.status_code in (401, 403)
