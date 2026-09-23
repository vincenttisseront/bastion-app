"""Unit coverage for sessions_service helpers on the Sonar new-code period."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from app.web.sessions_service import (
    _aware,
    _canonical_email_map,
    _format_duration,
    _format_last_seen,
    _identity_keys_from_audit,
    _merge_sso_logout_audit_badge,
    _parse_iso_dt,
    _relative_ago,
    _sso_logout_badge,
)


def test_aware_and_parse_iso_dt():
    assert _aware(None) is None
    naive = datetime(2026, 1, 2, 3, 4, 5)
    aware = _aware(naive)
    assert aware is not None
    assert aware.tzinfo is timezone.utc
    already = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert _aware(already) is already

    assert _parse_iso_dt(None) is None
    assert _parse_iso_dt("") is None
    assert _parse_iso_dt(42) is None
    assert _parse_iso_dt("not-a-date") is None
    parsed = _parse_iso_dt("2026-01-02T03:04:05Z")
    assert parsed is not None
    assert parsed.tzinfo is not None
    assert _parse_iso_dt(already) is already


def test_format_duration_and_last_seen():
    start = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert _format_duration(start, start + timedelta(seconds=45)) == "45s"
    assert _format_duration(start, start + timedelta(minutes=3, seconds=5)) == "3m 05s"
    assert _format_duration(start, start + timedelta(hours=2, minutes=7)) == "2h 07m"
    assert _format_last_seen(None) == "—"
    assert "UTC" in _format_last_seen(start)


def test_relative_ago_buckets(monkeypatch):
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(
        "app.web.sessions_service.utcnow", lambda: now
    )
    assert _relative_ago(None) == "—"
    assert "s" in _relative_ago(now - timedelta(seconds=12))
    assert "min" in _relative_ago(now - timedelta(minutes=5))
    assert "h" in _relative_ago(now - timedelta(hours=3))
    assert "j" in _relative_ago(now - timedelta(days=2))


def test_sso_logout_badge_window(monkeypatch):
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr("app.web.sessions_service.utcnow", lambda: now)
    assert _sso_logout_badge(None, now=now) is None
    assert _sso_logout_badge(now - timedelta(hours=5), now=now) is None
    badge = _sso_logout_badge(now - timedelta(minutes=10), now=now)
    assert badge is not None
    assert "Déconnexion demandée" in badge["label"]


def test_identity_keys_and_merge_badge(monkeypatch):
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr("app.web.sessions_service.utcnow", lambda: now)
    entry = MagicMock()
    entry.details = {
        "ok": True,
        "user_email": "User@Example.com",
        "username": "user",
    }
    entry.target = "User@Example.com"
    entry.created_at = now - timedelta(minutes=5)
    keys = _identity_keys_from_audit(entry)
    assert "user@example.com" in keys
    assert "user" in keys

    out: dict = {}
    _merge_sso_logout_audit_badge(out, entry, now=now)
    assert "user@example.com" in out

    fail = MagicMock(details={"ok": False}, target="x", created_at=now)
    _merge_sso_logout_audit_badge(out, fail, now=now)
    assert "x" not in out or out.get("x") == out.get("user@example.com")


def test_canonical_email_map_prefers_longer():
    sessions = [
        {"realm": "Default", "user_email": "a@example.com", "user": "a"},
        {"realm": "default", "user_email": "", "user": "alice@example.com"},
        {"realm": "default", "user_email": "not-an-email", "user": ""},
    ]
    mapped = _canonical_email_map(sessions)
    assert mapped[("default", "a")] == "a@example.com"
    assert mapped[("default", "alice")] == "alice@example.com"


def test_ua_label_from_details_variants():
    from app.web.sessions_service import _LBL_SERVER_DRIVER_SESSION, _ua_label_from_details

    label, note = _ua_label_from_details(
        {"driver": "crushftp"}, presence_only=False, browser_note=None
    )
    assert label == _LBL_SERVER_DRIVER_SESSION
    assert note

    label, _note = _ua_label_from_details(
        {"source": "subdomain_auth"}, presence_only=True, browser_note=None
    )
    assert "SSO" in label

    label, _note = _ua_label_from_details(
        {"user_agent": "Mozilla/5.0"}, presence_only=False, browser_note=None
    )
    assert label
