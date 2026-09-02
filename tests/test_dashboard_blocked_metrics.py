"""Dashboard blocked-attempts KPI — 24h WAF + auth, not all-time audit."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from sqlalchemy.orm import Session

from app.models import AuditLog, SecurityBan, utcnow
from app.sso_settings import Settings
from app.web.metrics_service import get_dashboard_metrics


def _settings() -> Settings:
    return Settings(
        environment="test",
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        breakglass_jwt_secret_fallback_enabled=True,
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )


def test_blocked_attempts_sums_waf_and_recent_auth(db_session: Session):
    now = utcnow()
    db_session.add_all(
        [
            AuditLog(
                actor="x",
                action="oidc_login_failed",
                created_at=now - timedelta(hours=1),
            ),
            AuditLog(
                actor="x",
                action="access_denied_unknown_host",
                created_at=now - timedelta(hours=2),
            ),
            # Outside 24h window — must not count
            AuditLog(
                actor="x",
                action="oidc_login_failed",
                created_at=now - timedelta(hours=48),
            ),
            # Admin device block — must not count (not an attempt)
            AuditLog(
                actor="admin",
                action="activesync.device_blocked",
                created_at=now - timedelta(minutes=10),
            ),
            SecurityBan(
                target_type="ip",
                target="1.2.3.4",
                reason="test",
                permanent=True,
            ),
        ]
    )
    db_session.commit()

    with patch(
        "app.web.metrics_service.read_audit_summary",
        return_value={
            "present": True,
            "log_available": True,
            "windows": {"24h": {"blocks": 5, "detections": 12}},
        },
    ):
        metrics = get_dashboard_metrics(db_session, _settings())

    assert metrics["blocked_attempts_waf"] == 5
    assert metrics["blocked_attempts_auth"] == 2
    assert metrics["blocked_attempts"] == 7
    assert metrics["blocked_attempts_window_hours"] == 24
    assert metrics["blocked_attempts_active_bans"] == 1


def test_blocked_attempts_without_waf_summary_uses_auth_only(db_session: Session):
    db_session.add(
        AuditLog(actor="x", action="security.rate_limited", created_at=utcnow())
    )
    db_session.commit()

    with patch(
        "app.web.metrics_service.read_audit_summary",
        return_value={"present": False, "log_available": False},
    ):
        metrics = get_dashboard_metrics(db_session, _settings())

    assert metrics["blocked_attempts_auth"] == 1
    assert metrics["blocked_attempts_waf"] == 0
    assert metrics["blocked_attempts_waf_available"] is False
    assert metrics["blocked_attempts"] == 1
