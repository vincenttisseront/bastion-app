"""Live verification of driven CrushFTP / generic_form sessions."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.bastion.drivers.base import RoboticLoginError
from app.models import ActiveSession, App, utcnow
from app.web.session_verify import verify_crushftp_session



def _driven_row(
    db: Session,
    *,
    email: str = "alice@example.com",
    slug: str = "transfer",
    cookies: dict | None = None,
    username: str = "vincent",
) -> ActiveSession:
    app = App(
        slug=slug,
        label="Transfer",
        upstream_url="https://transfer.example.com/",
        enabled=True,
        access_mode="subdomain_proxy",
        public_fqdn="transfer.example.com",
        robotic_driver="crushftp",
    )
    db.add(app)
    row = ActiveSession(
        id=f"app:{email}:{slug}",
        kind="app",
        user_email=email,
        username="alice",
        realm="ar-systems",
        protocol="HTTPS",
        target=slug,
        source_ip="203.0.113.10",
        status="active",
        started_at=utcnow(),
        last_seen_at=utcnow(),
        details={
            "driver": "crushftp",
            "verifiable": True,
            "robotic_username": username,
            "verify_base_url": "https://transfer.example.com/",
            "session_cookies": cookies
            or {"CrushAuth": "123_abc", "currentAuth": "cAuth"},
            "app_label": "Transfer",
        },
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
    "X-Portal-Realm-Slug": "ar-systems",
}


@pytest.mark.asyncio
async def test_verify_crushftp_active():
    details = {
        "session_cookies": {"CrushAuth": "x", "currentAuth": "y"},
        "verify_base_url": "https://transfer.example.com/",
        "robotic_username": "vincent",
    }
    with patch(
        "app.web.session_verify.CrushFTPDriver.get_username",
        new=AsyncMock(return_value="vincent"),
    ):
        assert await verify_crushftp_session(details) == "active"


@pytest.mark.asyncio
async def test_verify_crushftp_invalid_on_login_error():
    details = {
        "session_cookies": {"CrushAuth": "x", "currentAuth": "y"},
        "verify_base_url": "https://transfer.example.com/",
        "robotic_username": "vincent",
    }
    with patch(
        "app.web.session_verify.CrushFTPDriver.get_username",
        new=AsyncMock(side_effect=RoboticLoginError("rejected")),
    ):
        assert await verify_crushftp_session(details) == "invalid"


@pytest.mark.asyncio
async def test_verify_crushftp_unknown_without_cookies():
    assert await verify_crushftp_session({"session_cookies": {}, "verify_base_url": "https://x/"}) == "unknown"


def test_driven_session_default_live_status_unverified(client: TestClient, db_session: Session):
    _driven_row(db_session)
    api = client.get("/api/sessions", headers=ADMIN_HEADERS).json()
    app_sess = next(s for s in api["sessions"] if s["kind"] == "app")
    assert app_sess["verifiable"] is True
    assert app_sess["live_status"] == "unverified"
    assert app_sess["live_status_label"] == "NON VÉRIFIÉ"
    assert "session_cookies" not in (app_sess.get("details") or {})


def test_live_verify_updates_status(client: TestClient, db_session: Session):
    row = _driven_row(db_session)
    with patch(
        "app.web.session_verify.CrushFTPDriver.get_username",
        new=AsyncMock(return_value="vincent"),
    ):
        resp = client.post(
            "/api/sessions/live-verify",
            headers=ADMIN_HEADERS,
            json={"user_email": "alice@example.com"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["verified"]
    assert body["verified"][0]["last_verified_status"] == "active"
    db_session.refresh(row)
    assert row.last_verified_status == "active"
    assert row.last_verified_at is not None

    api = client.get("/api/sessions", headers=ADMIN_HEADERS).json()
    app_sess = next(s for s in api["sessions"] if s["id"] == row.id)
    assert app_sess["live_status"] == "active"
    assert app_sess["live_status_label"] == "ACTIVE"


def test_live_verify_invalid(client: TestClient, db_session: Session):
    row = _driven_row(db_session)
    with patch(
        "app.web.session_verify.CrushFTPDriver.get_username",
        new=AsyncMock(side_effect=RoboticLoginError("rejected")),
    ):
        resp = client.post(
            "/api/sessions/live-verify",
            headers=ADMIN_HEADERS,
            json={"user_email": "alice@example.com"},
        )
    assert resp.status_code == 200
    db_session.refresh(row)
    assert row.last_verified_status == "invalid"
    api = client.get("/api/sessions", headers=ADMIN_HEADERS).json()
    app_sess = next(s for s in api["sessions"] if s["id"] == row.id)
    assert app_sess["live_status"] == "invalid"
    assert app_sess["live_status_label"] == "INVALIDE"
