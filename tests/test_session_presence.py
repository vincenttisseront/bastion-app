"""subdomain-auth presence heartbeat for live /sessions."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from app.models import ActiveSession, App, utcnow
from app.web.sessions_service import (
    PRESENCE_THROTTLE_SECONDS,
    _aware,
    _row_to_dict,
    touch_app_presence,
)


def _app(db: Session, *, slug: str = "webmail") -> App:
    app = App(
        slug=slug,
        label="Grommunio",
        upstream_url=f"https://{slug}.internal/",
        enabled=True,
        access_mode="subdomain_proxy",
        public_fqdn=f"{slug}.ar-systems.fr",
        realm_slug="ar-systems",
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def test_touch_app_presence_creates_presence_only_row(db_session: Session):
    app = _app(db_session)
    row = touch_app_presence(
        db_session,
        email="alice@example.com",
        username="alice",
        realm="ar-systems",
        app=app,
        source_ip="203.0.113.9",
        auth_source="oidc",
    )
    assert row is not None
    assert row.kind == "app"
    assert row.target == "webmail"
    assert row.user_email == "alice@example.com"
    details = row.details or {}
    assert details.get("presence_only") is True
    assert details.get("source") == "subdomain_auth"
    assert "session_cookies" not in details

    payload = _row_to_dict(row)
    assert payload["presence_only"] is True
    assert payload["live_status"] == "presence"
    assert payload["live_status_label"] == "ACTIVITÉ SSO"


def test_touch_app_presence_throttles_within_window(db_session: Session):
    app = _app(db_session)
    first = touch_app_presence(
        db_session,
        email="alice@example.com",
        username="alice",
        realm="ar-systems",
        app=app,
        source_ip="203.0.113.9",
        auth_source="oidc",
        throttle_seconds=PRESENCE_THROTTLE_SECONDS,
    )
    assert first is not None
    first_seen = first.last_seen_at
    first_id = first.id

    second = touch_app_presence(
        db_session,
        email="alice@example.com",
        username="alice",
        realm="ar-systems",
        app=app,
        source_ip="198.51.100.1",
        auth_source="oidc",
        throttle_seconds=PRESENCE_THROTTLE_SECONDS,
    )
    assert second is not None
    assert second.id == first_id
    # No DB write → last_seen unchanged; source_ip not updated either.
    db_session.refresh(second)
    assert second.last_seen_at == first_seen
    assert second.source_ip == "203.0.113.9"


def test_touch_app_presence_updates_after_throttle(db_session: Session):
    app = _app(db_session)
    first = touch_app_presence(
        db_session,
        email="alice@example.com",
        username="alice",
        realm="ar-systems",
        app=app,
        source_ip="203.0.113.9",
        auth_source="oidc",
        throttle_seconds=60,
    )
    assert first is not None
    old_seen = utcnow() - timedelta(seconds=61)
    first.last_seen_at = old_seen
    db_session.commit()

    second = touch_app_presence(
        db_session,
        email="alice@example.com",
        username="alice",
        realm="ar-systems",
        app=app,
        source_ip="198.51.100.1",
        auth_source="oidc",
        throttle_seconds=60,
    )
    assert second is not None
    db_session.refresh(second)
    assert _aware(second.last_seen_at) > _aware(old_seen)
    assert (second.details or {}).get("last_presence_at")
    # prefer_client_ip keeps the first real client IP — heartbeat must not flip it.
    assert second.source_ip == "203.0.113.9"


def test_touch_app_presence_preserves_session_cookies(db_session: Session):
    app = _app(db_session)
    cookies = {"__Secure-GROMMUNIO_WEB": "sess-abc"}
    seeded = ActiveSession(
        id="app:alice@example.com:webmail",
        kind="app",
        user_email="alice@example.com",
        username="alice",
        realm="ar-systems",
        protocol="HTTPS",
        target="webmail",
        source_ip="203.0.113.9",
        status="active",
        started_at=utcnow() - timedelta(hours=1),
        last_seen_at=utcnow() - timedelta(seconds=120),
        details={
            "session_cookies": cookies,
            "verifiable": True,
            "driver": "generic_form",
            "cookies_present": list(cookies.keys()),
            "cookies_ok": True,
            "presence_only": False,
        },
    )
    db_session.add(seeded)
    db_session.commit()

    touch_app_presence(
        db_session,
        email="alice@example.com",
        username="alice",
        realm="ar-systems",
        app=app,
        source_ip="203.0.113.9",
        auth_source="oidc",
        throttle_seconds=0,
    )
    row = db_session.query(ActiveSession).filter_by(id=seeded.id).one()
    details = row.details or {}
    assert details.get("session_cookies") == cookies
    assert details.get("driver") == "generic_form"
    assert details.get("presence_only") is False
    assert details.get("source") == "subdomain_auth"

    payload = _row_to_dict(row)
    assert payload["presence_only"] is False
    assert payload["verifiable"] is True
    assert payload["live_status_label"] == "NON VÉRIFIÉ"
