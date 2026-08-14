"""Daily ops recap email (SMTP) — domains, pending accounts, alerts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from sqlalchemy.orm import Session

from app.audit import log_action
from app.mail.recap_service import (
    build_daily_recap,
    daily_recap_job,
    format_recap_email,
    recap_timezone,
    send_daily_recap,
)
from app.models import (
    AccessRequest,
    AuditLog,
    PendingHost,
    PendingUser,
    SecurityBan,
    utcnow,
)
from app.portal_settings_service import ensure_portal_settings
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )


def _enable_smtp(db: Session, *, recap: bool = True) -> None:
    s = _settings()
    row = ensure_portal_settings(db, s)
    row.smtp_enabled = True
    row.smtp_host = "smtp.example.com"
    row.smtp_port = 587
    row.smtp_use_tls = True
    row.smtp_username = "mailer"
    row.smtp_password_encrypted = encrypt_secret("smtp-pass", s)
    row.smtp_from_email = "noreply@example.com"
    row.smtp_from_name = "Bastion"
    row.daily_recap_enabled = recap
    row.daily_recap_email = "ops@example.com"
    row.daily_recap_hour = 7
    db.commit()


def test_build_daily_recap_includes_hosts_users_alerts(db_session: Session):
    now = utcnow()
    db_session.add(
        PendingHost(
            hostname="new-app.example.com",
            first_seen_at=now - timedelta(hours=2),
            last_seen_at=now,
            hit_count=4,
            last_client_ip="10.1.2.3",
            status="pending",
        )
    )
    db_session.add(
        PendingHost(
            hostname="discovery-probe-1700000000.example.com",
            first_seen_at=now - timedelta(hours=1),
            last_seen_at=now,
            status="pending",
        )
    )
    db_session.add(
        PendingUser(
            user_email="alice@example.com",
            username="alice",
            realm_slug="ar-systems",
            first_seen_at=now - timedelta(hours=3),
            last_seen_at=now,
            status="pending",
        )
    )
    db_session.add(
        AccessRequest(
            username="bob",
            email="bob@example.com",
            organization="OrgCo",
            status="pending",
            created_at=now - timedelta(hours=1),
        )
    )
    db_session.add(
        SecurityBan(
            target_type="ip",
            target="203.0.113.9",
            reason="hammering",
            rule_type="hammering",
            banned_at=now - timedelta(hours=1),
        )
    )
    db_session.commit()
    log_action(
        db_session,
        actor="admin@example.com",
        action="breakglass.login_failed",
        ip_address="10.0.0.1",
        forward_to_siem=False,
    )

    recap = build_daily_recap(db_session, _settings())
    host_titles = [line.title for line in recap.new_hosts]
    assert "new-app.example.com" in host_titles
    assert not any("discovery-probe" in t for t in host_titles)
    assert recap.pending_hosts_total == 1
    assert recap.new_hosts_count == 1
    assert recap.pending_users_total == 1
    assert recap.pending_access_total == 1
    assert recap.alerts_total >= 1
    assert any("breakglass" in (a.title + a.detail).lower() or "BST-BGL" in a.title for a in recap.alerts)
    assert recap.bans
    assert recap.bans[0].title == "ip:203.0.113.9"

    subject, text, html = format_recap_email(recap)
    assert "Récap 24h" in subject
    assert "new-app.example.com" in text
    assert "alice@example.com" in text
    assert "bob@example.com" in text
    assert "203.0.113.9" in text
    assert "discovery-probe" not in text
    assert "new-app.example.com" in html
    assert "https://portal.test/admin/pending-hosts" in html


def test_send_daily_recap_skips_when_disabled(db_session: Session):
    _enable_smtp(db_session, recap=False)
    result = send_daily_recap(db_session, _settings(), force=False)
    assert result.status == "skipped_disabled"


def test_send_daily_recap_skips_when_smtp_off(db_session: Session):
    row = ensure_portal_settings(db_session, _settings())
    row.daily_recap_enabled = True
    db_session.commit()
    result = send_daily_recap(db_session, _settings(), force=True)
    assert result.status == "skipped_smtp"


def test_send_daily_recap_skips_before_hour(db_session: Session):
    _enable_smtp(db_session, recap=True)
    tz = recap_timezone()
    too_early = datetime(2026, 8, 14, 6, 10, tzinfo=tz)
    result = send_daily_recap(db_session, _settings(), now=too_early)
    assert result.status == "skipped_hour"


def test_send_daily_recap_skips_already_sent(db_session: Session):
    _enable_smtp(db_session, recap=True)
    row = ensure_portal_settings(db_session, _settings())
    tz = recap_timezone()
    now = datetime(2026, 8, 14, 8, 10, tzinfo=tz)
    row.daily_recap_last_sent_at = now.astimezone(UTC)
    db_session.commit()
    result = send_daily_recap(db_session, _settings(), now=now)
    assert result.status == "skipped_already"


def test_send_daily_recap_sends_when_due(db_session: Session):
    _enable_smtp(db_session, recap=True)
    tz = recap_timezone()
    now = datetime(2026, 8, 14, 7, 10, tzinfo=tz)
    with patch("app.mail.recap_service.send_email") as mock_send:
        result = send_daily_recap(db_session, _settings(), now=now)
    assert result.status == "sent"
    mock_send.assert_called_once()
    kwargs = mock_send.call_args.kwargs
    assert kwargs["to_email"] == "ops@example.com"
    assert "Récap 24h" in kwargs["subject"]
    row = ensure_portal_settings(db_session, _settings())
    assert row.daily_recap_last_sent_at is not None
    logged = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "portal_settings.daily_recap_sent")
        .one()
    )
    assert logged.event_code == "BST-ADM-0008"


def test_send_daily_recap_force_ignores_hour(db_session: Session):
    _enable_smtp(db_session, recap=False)
    tz = recap_timezone()
    too_early = datetime(2026, 8, 14, 3, 0, tzinfo=tz)
    with patch("app.mail.recap_service.send_email") as mock_send:
        result = send_daily_recap(
            db_session, _settings(), force=True, now=too_early, actor="admin@example.com"
        )
    assert result.status == "sent"
    mock_send.assert_called_once()


def test_daily_recap_job_never_raises():
    with patch(
        "app.mail.recap_service.send_daily_recap",
        side_effect=RuntimeError("boom"),
    ), patch("app.database.SessionLocal") as session_cls:
        session_cls.return_value = MagicMock()
        daily_recap_job(_settings())


def test_configuration_page_shows_recap_fields(client, db_session: Session):
    _enable_smtp(db_session, recap=True)
    page = client.get("/admin/configuration", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    assert "Récapitulatif quotidien" in page.text
    assert 'name="daily_recap_enabled"' in page.text
    assert 'action="/admin/configuration/smtp/recap"' in page.text
    assert 'id="daily_recap_email"' in page.text


def test_configuration_saves_recap_settings(client, db_session: Session):
    _enable_smtp(db_session, recap=False)
    resp = client.post(
        "/admin/configuration",
        headers=ADMIN_HEADERS,
        data={
            "smtp_enabled": "on",
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
            "smtp_use_tls": "on",
            "smtp_username": "mailer",
            "smtp_from_email": "noreply@example.com",
            "smtp_from_name": "Bastion",
            "daily_recap_enabled": "on",
            "daily_recap_email": "soc@example.com",
            "daily_recap_hour": "8",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    row = ensure_portal_settings(db_session, _settings())
    db_session.refresh(row)
    assert row.daily_recap_enabled is True
    assert row.daily_recap_email == "soc@example.com"
    assert row.daily_recap_hour == 8


def test_configuration_send_recap_now(client, db_session: Session):
    _enable_smtp(db_session, recap=True)
    with patch("app.mail.recap_service.send_email") as mock_send:
        resp = client.post(
            "/admin/configuration/smtp/recap",
            headers=ADMIN_HEADERS,
            follow_redirects=False,
        )
    assert resp.status_code == 302
    mock_send.assert_called_once()
