"""Anti-abuse / banning engine tests."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy.orm import Session

from app.models import AuditLog, SecurityBan
from app.models import utcnow
from app.security.banning.engine import (
    RULE_FAILED_LOGIN,
    RULE_HACK_USERNAME,
    RULE_HAMMERING,
    apply_ban,
    clear_counters_for_tests,
    ensure_security_defaults,
    evaluate_login_attempt,
    find_active_ban,
    get_rule,
    is_breakglass_ip_allowed,
    lift_expired_bans,
    record_sensitive_request,
)
from app.security.banning.service import add_allowlist_entry, update_ban_rules


@pytest.fixture(autouse=True)
def _reset_banning(db_session: Session):
    clear_counters_for_tests()
    ensure_security_defaults(db_session)
    yield
    clear_counters_for_tests()


def test_security_hammering_threshold_triggers_ban(db_session: Session):
    update_ban_rules(
        db_session,
        rules={
            RULE_HAMMERING: {
                "enabled": True,
                "threshold": 5,
                "window_seconds": 60,
                "ban_minutes": 10,
                "ban_permanent": False,
            }
        },
        actor="test",
    )
    ip = "203.0.113.10"
    for _ in range(4):
        assert record_sensitive_request(db_session, ip=ip, path="/admin/security") is None
    assert find_active_ban(db_session, ip=ip) is None

    ban = record_sensitive_request(db_session, ip=ip, path="/admin/security")
    assert ban is not None
    assert ban.target == ip
    assert ban.rule_type == RULE_HAMMERING
    assert ban.permanent is False
    assert ban.expires_at is not None


def test_security_hack_username_immediate_ban(db_session: Session):
    update_ban_rules(
        db_session,
        rules={
            RULE_HACK_USERNAME: {
                "enabled": True,
                "usernames": ["administrator", "admin", "root"],
                "ban_minutes": 60,
                "ban_permanent": False,
            }
        },
        actor="test",
    )
    ip = "198.51.100.20"
    result = evaluate_login_attempt(
        db_session, ip=ip, username="administrator", success=True
    )
    assert result.allowed is False
    assert result.hack_attempt is True
    assert result.ban is not None
    assert result.ban.target == ip
    assert result.ban.rule_type == RULE_HACK_USERNAME

    audit = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "security.hack_attempt.detected")
        .all()
    )
    assert len(audit) >= 1


def test_security_allowlist_never_banned(db_session: Session):
    update_ban_rules(
        db_session,
        rules={
            RULE_HAMMERING: {
                "enabled": True,
                "threshold": 2,
                "window_seconds": 60,
                "ban_minutes": 10,
            },
            RULE_HACK_USERNAME: {
                "enabled": True,
                "usernames": ["admin"],
                "ban_minutes": 60,
            },
            RULE_FAILED_LOGIN: {
                "enabled": True,
                "threshold": 2,
                "window_seconds": 60,
                "ban_minutes": 10,
                "ban_username": True,
            },
        },
        actor="test",
    )
    ip = "203.0.113.50"
    add_allowlist_entry(
        db_session,
        entry_type="ip",
        value=ip,
        comment="monitor",
        actor="test",
    )
    add_allowlist_entry(
        db_session,
        entry_type="username",
        value="healthcheck",
        comment="svc",
        actor="test",
    )

    for _ in range(10):
        assert record_sensitive_request(db_session, ip=ip, path="/admin") is None
    assert find_active_ban(db_session, ip=ip) is None

    hack = evaluate_login_attempt(
        db_session, ip=ip, username="admin", success=True
    )
    assert hack.allowed is True
    assert find_active_ban(db_session, ip=ip) is None

    for _ in range(5):
        evaluate_login_attempt(
            db_session, ip="198.51.100.99", username="healthcheck", success=False
        )
    assert find_active_ban(db_session, username="healthcheck") is None


def test_security_ban_expiry_auto_lift(db_session: Session):
    ban = apply_ban(
        db_session,
        target_type="ip",
        target="203.0.113.77",
        reason="test expiry",
        rule_type="manual",
        permanent=False,
        ban_minutes=1,
        actor="test",
        confirm_permanent=False,
    )
    assert ban is not None
    ban.expires_at = utcnow() - timedelta(seconds=5)
    db_session.commit()

    assert find_active_ban(db_session, ip="203.0.113.77") is None
    lifted = (
        db_session.query(SecurityBan)
        .filter(SecurityBan.id == ban.id)
        .one()
    )
    # find_active_ban calls lift_expired_bans
    assert lifted.lifted_at is not None

    n = lift_expired_bans(db_session)
    assert n == 0  # already lifted


def test_security_audit_ban_events(db_session: Session):
    ban = apply_ban(
        db_session,
        target_type="ip",
        target="203.0.113.88",
        reason="audit test",
        rule_type="manual",
        permanent=False,
        ban_minutes=5,
        actor="admin@test",
        ip_address="10.0.0.1",
    )
    assert ban is not None
    applied = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "security.ban.applied")
        .all()
    )
    assert any(a.target == "ip:203.0.113.88" for a in applied)

    ban.expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()
    lift_expired_bans(db_session)
    lifted = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "security.ban.lifted")
        .all()
    )
    assert any(a.target == "ip:203.0.113.88" for a in lifted)


def test_security_permanent_requires_confirmation(db_session: Session):
    refused = apply_ban(
        db_session,
        target_type="ip",
        target="203.0.113.1",
        reason="no confirm",
        rule_type="manual",
        permanent=True,
        ban_minutes=0,
        actor="test",
        confirm_permanent=False,
    )
    assert refused is None

    ok = apply_ban(
        db_session,
        target_type="ip",
        target="203.0.113.1",
        reason="confirmed",
        rule_type="manual",
        permanent=True,
        ban_minutes=0,
        actor="test",
        confirm_permanent=True,
    )
    assert ok is not None
    assert ok.permanent is True
    assert ok.expires_at is None


def test_security_breakglass_deny_and_allow_cidrs(db_session: Session):
    from app.security.banning.service import update_policy_misc

    update_policy_misc(
        db_session,
        enabled=True,
        breakglass_allow_cidrs="10.5.0.0/16",
        breakglass_deny_cidrs="10.5.9.0/24",
        actor="test",
    )
    rfc = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    assert is_breakglass_ip_allowed(db_session, "10.5.1.10", rfc1918_cidrs=rfc) is True
    assert is_breakglass_ip_allowed(db_session, "10.5.9.5", rfc1918_cidrs=rfc) is False
    assert is_breakglass_ip_allowed(db_session, "192.168.1.1", rfc1918_cidrs=rfc) is False


def test_security_failed_login_bans_ip_after_threshold(db_session: Session):
    update_ban_rules(
        db_session,
        rules={
            RULE_FAILED_LOGIN: {
                "enabled": True,
                "threshold": 3,
                "window_seconds": 120,
                "ban_minutes": 15,
                "ban_username": True,
            }
        },
        actor="test",
    )
    ip = "203.0.113.33"
    for _ in range(2):
        r = evaluate_login_attempt(
            db_session, ip=ip, username="vincent", success=False
        )
        assert r.allowed is True
    r = evaluate_login_attempt(
        db_session, ip=ip, username="vincent", success=False
    )
    assert r.allowed is False
    assert find_active_ban(db_session, ip=ip) is not None
    assert find_active_ban(db_session, username="vincent") is not None


def test_get_rule_seeded(db_session: Session):
    assert get_rule(db_session, RULE_HAMMERING) is not None
    assert get_rule(db_session, RULE_HACK_USERNAME) is not None
