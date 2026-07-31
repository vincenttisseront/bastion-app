"""F-01: break-glass POST /auth/login must be LAN-only (defense in depth)."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.breakglass_store import set_breakglass_password
from app.models import AuditLog
from tests.test_auth_login_flow import _add_default_idp


def test_breakglass_login_rejected_from_public_ip(
    client: TestClient, db_session: Session
):
    _add_default_idp(db_session)
    set_breakglass_password(db_session, "admin", "super-secret-password")

    response = client.post(
        "/auth/login",
        data={
            "username": "admin",
            "password": "super-secret-password",
            "rd": "/dashboard",
        },
        headers={"X-Real-IP": "203.0.113.10"},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "bg_session" not in response.cookies
    assert "Identifiants invalides" in response.text
    denied = (
        db_session.query(AuditLog)
        .filter_by(action="breakglass.login_denied_non_lan")
        .count()
    )
    assert denied >= 1


def test_breakglass_login_allowed_from_rfc1918_ip(
    client: TestClient, db_session: Session
):
    _add_default_idp(db_session)
    set_breakglass_password(db_session, "admin", "super-secret-password")

    response = client.post(
        "/auth/login",
        data={
            "username": "admin",
            "password": "super-secret-password",
            "rd": "/dashboard",
        },
        headers={"X-Real-IP": "192.168.1.50"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == "/dashboard"
    assert "bg_session" in response.cookies


def test_login_page_hides_breakglass_from_public_ip(
    client: TestClient, db_session: Session
):
    _add_default_idp(db_session)
    set_breakglass_password(db_session, "admin", "super-secret-password")

    response = client.get(
        "/auth/login",
        headers={"X-Real-IP": "203.0.113.10"},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Connexion SSO Keycloak" in response.text
    assert "break-glass" not in response.text.lower()
    assert "ou accès local" not in response.text
    assert 'name="username"' not in response.text
    assert 'name="password"' not in response.text
    assert 'action="/auth/login"' not in response.text


def test_login_page_shows_breakglass_from_lan_ip(
    client: TestClient, db_session: Session
):
    _add_default_idp(db_session)
    set_breakglass_password(db_session, "admin", "super-secret-password")

    response = client.get(
        "/auth/login",
        headers={"X-Real-IP": "10.0.0.50"},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Accès break-glass administrateur" in response.text
    assert "ou accès local" in response.text
    assert 'name="username"' in response.text
