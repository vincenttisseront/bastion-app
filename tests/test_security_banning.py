"""Anti-abuse / banning engine tests."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import AuditLog, SecurityBan, SecurityRateEvent
from app.models import utcnow
from app.security.banning.engine import (
    RULE_FAILED_LOGIN,
    RULE_HACK_USERNAME,
    RULE_HAMMERING,
    RULE_HAMMERING_LOGIN,
    RULE_SUCCESSFUL_LOGIN,
    RULE_UNKNOWN_HOST,
    apply_ban,
    check_request_allowed,
    clear_counters_for_tests,
    ensure_security_defaults,
    evaluate_login_attempt,
    find_active_ban,
    get_rule,
    is_breakglass_ip_allowed,
    lift_expired_bans,
    record_sensitive_request,
    record_successful_login,
    record_unknown_host_refusal,
)
from app.security.banning.service import add_allowlist_entry, update_ban_rules


@pytest.fixture(autouse=True)
def _reset_banning(db_session: Session):
    clear_counters_for_tests(db_session)
    ensure_security_defaults(db_session)
    yield
    clear_counters_for_tests(db_session)


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


def test_unknown_host_hammering_bans_scanner_ip(db_session: Session):
    update_ban_rules(
        db_session,
        rules={
            RULE_UNKNOWN_HOST: {
                "enabled": True,
                "threshold": 5,
                "window_seconds": 300,
                "ban_minutes": 60,
            }
        },
        actor="test",
    )
    ip = "34.155.98.34"
    for _ in range(4):
        assert (
            record_unknown_host_refusal(
                db_session, ip=ip, hostname="ar-systems.fr", uri="/api/v2/settings"
            )
            is None
        )
    ban = record_unknown_host_refusal(
        db_session, ip=ip, hostname="ar-systems.fr", uri="/api/v2/settings"
    )
    assert ban is not None
    assert ban.target == ip
    assert ban.rule_type == RULE_UNKNOWN_HOST
    assert find_active_ban(db_session, ip=ip) is not None
    audit = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "security.unknown_host_hammering.detected")
        .one()
    )
    assert audit.ip_address == ip
    assert audit.event_code == "BST-WAF-2007"


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
    assert get_rule(db_session, RULE_HAMMERING_LOGIN) is not None
    assert get_rule(db_session, RULE_SUCCESSFUL_LOGIN) is not None
    assert get_rule(db_session, RULE_HACK_USERNAME) is not None


def test_security_sso_failed_login_feeds_counter(client: TestClient, db_session: Session):
    update_ban_rules(
        db_session,
        rules={
            RULE_FAILED_LOGIN: {
                "enabled": True,
                "threshold": 2,
                "window_seconds": 300,
                "ban_minutes": 10,
                "ban_username": True,
            },
            RULE_HAMMERING: {"enabled": False},
            RULE_HAMMERING_LOGIN: {"enabled": False},
        },
        actor="test",
    )
    resp = client.get("/auth/sso-failed?error=access_denied&username=alice")
    assert resp.status_code == 200
    assert "Connexion SSO échouée" in resp.text
    audit = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "security.sso_login_failed")
        .all()
    )
    assert len(audit) >= 1

    clear_counters_for_tests(db_session)
    ip = "203.0.113.41"
    assert (
        evaluate_login_attempt(
            db_session, ip=ip, username="carol", success=False
        ).allowed
        is True
    )
    assert (
        evaluate_login_attempt(
            db_session, ip=ip, username="carol", success=False
        ).allowed
        is False
    )
    assert find_active_ban(db_session, ip=ip) is not None
    assert find_active_ban(db_session, username="carol") is not None


def test_security_successful_login_hammering(db_session: Session):
    update_ban_rules(
        db_session,
        rules={
            RULE_SUCCESSFUL_LOGIN: {
                "enabled": True,
                "threshold": 3,
                "window_seconds": 120,
                "ban_minutes": 15,
                "ban_permanent": False,
            }
        },
        actor="test",
    )
    ip = "203.0.113.55"
    for _ in range(2):
        assert (
            record_successful_login(db_session, ip=ip, username="bob@example.com")
            is None
        )
    ban = record_successful_login(db_session, ip=ip, username="bob@example.com")
    assert ban is not None
    assert ban.target_type == "username"
    assert ban.target == "bob@example.com"
    assert ban.rule_type == RULE_SUCCESSFUL_LOGIN
    assert find_active_ban(db_session, username="bob@example.com") is not None
    assert find_active_ban(db_session, ip=ip) is None
    detected = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "security.successful_login_hammering.detected")
        .all()
    )
    assert len(detected) >= 1


def test_security_login_only_counter(db_session: Session):
    update_ban_rules(
        db_session,
        rules={
            RULE_HAMMERING: {"enabled": False},
            RULE_HAMMERING_LOGIN: {
                "enabled": True,
                "threshold": 3,
                "window_seconds": 60,
                "ban_minutes": 10,
            },
        },
        actor="test",
    )
    ip = "203.0.113.60"
    for _ in range(5):
        assert record_sensitive_request(db_session, ip=ip, path="/admin") is None
    assert find_active_ban(db_session, ip=ip) is None

    for _ in range(2):
        assert (
            record_sensitive_request(
                db_session, ip=ip, path="/auth/login", method="POST"
            )
            is None
        )
    ban = record_sensitive_request(
        db_session, ip=ip, path="/auth/sso-start", method="GET"
    )
    assert ban is not None
    assert ban.rule_type == RULE_HAMMERING_LOGIN


def test_security_admin_username_ban(db_session: Session):
    apply_ban(
        db_session,
        target_type="username",
        target="banned.user@example.com",
        reason="manual",
        rule_type="manual",
        permanent=False,
        ban_minutes=30,
        actor="test",
        confirm_permanent=False,
    )
    allowed, reason, ban = check_request_allowed(
        db_session,
        ip="203.0.113.70",
        path="/admin/security",
        method="GET",
        username="banned.user@example.com",
    )
    assert allowed is False
    assert reason == "banned"
    assert ban is not None

    allowed2, _, _ = check_request_allowed(
        db_session,
        ip="203.0.113.70",
        path="/admin/security",
        method="GET",
        username="other@example.com",
    )
    assert allowed2 is True


def test_security_shared_counters(db_session: Session):
    update_ban_rules(
        db_session,
        rules={
            RULE_HAMMERING: {
                "enabled": True,
                "threshold": 100,
                "window_seconds": 60,
                "ban_minutes": 10,
            },
            RULE_HAMMERING_LOGIN: {"enabled": False},
        },
        actor="test",
    )
    ip = "203.0.113.80"
    assert record_sensitive_request(db_session, ip=ip, path="/admin") is None
    assert record_sensitive_request(db_session, ip=ip, path="/admin") is None
    n = (
        db_session.query(SecurityRateEvent)
        .filter(
            SecurityRateEvent.kind == "hammer",
            SecurityRateEvent.key == ip,
        )
        .count()
    )
    assert n == 2


def test_rate_limit_throttles_429_without_ban(db_session: Session):
    """Beyond the budget → rate_limited (429), NO ban row, audit once per burst."""
    from app.security.banning.engine import RULE_RATE_LIMIT

    update_ban_rules(
        db_session,
        rules={RULE_RATE_LIMIT: {"enabled": True, "threshold": 3, "window_seconds": 60}},
        actor="test",
    )
    ip = "203.0.113.90"
    for _ in range(3):
        allowed, reason, _ = check_request_allowed(
            db_session, ip=ip, path="/admin/security", method="GET"
        )
        assert allowed is True, reason

    for _ in range(2):
        allowed, reason, ban = check_request_allowed(
            db_session, ip=ip, path="/admin/security", method="GET"
        )
        assert allowed is False
        assert reason == "rate_limited"
        assert ban is None

    # Throttle, not ban — nothing in SecurityBan.
    assert find_active_ban(db_session, ip=ip) is None
    # Audit only on the FIRST rejection of the burst (no audit flood).
    audits = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "security.rate_limited")
        .all()
    )
    assert len(audits) == 1
    assert audits[0].details["rule_type"] == RULE_RATE_LIMIT
    assert audits[0].details["threshold"] == 3


def test_rate_limit_login_scope_only(db_session: Session):
    """Login budget throttles login paths but not other sensitive paths."""
    from app.security.banning.engine import RULE_RATE_LIMIT, RULE_RATE_LIMIT_LOGIN

    update_ban_rules(
        db_session,
        rules={
            RULE_RATE_LIMIT: {"enabled": False},
            RULE_RATE_LIMIT_LOGIN: {
                "enabled": True,
                "threshold": 2,
                "window_seconds": 60,
            },
        },
        actor="test",
    )
    ip = "203.0.113.91"
    for _ in range(2):
        allowed, reason, _ = check_request_allowed(
            db_session, ip=ip, path="/auth/login", method="POST"
        )
        assert allowed is True, reason

    allowed, reason, _ = check_request_allowed(
        db_session, ip=ip, path="/auth/login", method="POST"
    )
    assert allowed is False
    assert reason == "rate_limited"

    # Non-login sensitive path stays allowed (global rate limit disabled).
    allowed, reason, _ = check_request_allowed(
        db_session, ip=ip, path="/admin/security", method="GET"
    )
    assert allowed is True, reason
    assert find_active_ban(db_session, ip=ip) is None


def test_rate_limit_allowlisted_ip_never_throttled(db_session: Session):
    from app.security.banning.engine import RULE_RATE_LIMIT

    update_ban_rules(
        db_session,
        rules={RULE_RATE_LIMIT: {"enabled": True, "threshold": 1, "window_seconds": 60}},
        actor="test",
    )
    ip = "203.0.113.92"
    add_allowlist_entry(
        db_session, entry_type="ip", value=ip, comment="test", actor="test"
    )
    for _ in range(5):
        allowed, reason, _ = check_request_allowed(
            db_session, ip=ip, path="/admin/security", method="GET"
        )
        assert allowed is True, reason


def test_rate_limit_rules_ship_disabled_by_default(db_session: Session):
    from app.security.banning.engine import RULE_RATE_LIMIT, RULE_RATE_LIMIT_LOGIN

    rule = get_rule(db_session, RULE_RATE_LIMIT)
    assert rule is not None
    assert rule.enabled is False
    assert rule.threshold == 120
    login_rule = get_rule(db_session, RULE_RATE_LIMIT_LOGIN)
    assert login_rule is not None
    assert login_rule.enabled is False
    assert login_rule.threshold == 20


def test_rate_limit_middleware_returns_429_with_retry_after(
    client: TestClient, db_session: Session
):
    from app.security.banning.engine import RULE_RATE_LIMIT

    update_ban_rules(
        db_session,
        rules={RULE_RATE_LIMIT: {"enabled": True, "threshold": 2, "window_seconds": 45}},
        actor="test",
    )
    headers = {
        "X-Email": "admin@example.com",
        "X-Groups": "portal-admins",
        "X-Real-IP": "203.0.113.93",
    }
    for _ in range(2):
        resp = client.get("/admin/security", headers=headers)
        assert resp.status_code == 200

    resp = client.get("/admin/security", headers=headers)
    assert resp.status_code == 429
    assert resp.json()["detail"] == "Too many requests"
    assert resp.headers.get("Retry-After") == "45"
    # No ban row — throttle only.
    assert find_active_ban(db_session, ip="203.0.113.93") is None
    audits = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "security.rate_limited")
        .all()
    )
    assert len(audits) >= 1
    assert audits[0].target == "ip:203.0.113.93"


def test_security_banning_page_accordion_and_modals(client: TestClient, db_session: Session):
    resp = client.get(
        "/admin/security",
        headers={"X-Email": "admin@example.com", "X-Groups": "portal-admins"},
    )
    assert resp.status_code == 200
    body = resp.text
    assert 'id="banning"' in body
    assert "banning-accordion" in body
    assert "banning-rule-summary" in body
    assert 'data-banning-modal-open="ban-add-modal"' in body
    assert 'data-banning-modal-open="allowlist-add-modal"' in body
    assert 'id="ban-add-modal"' in body
    assert 'id="allowlist-add-modal"' in body
    assert "Ajouter un ban manuel" not in body
    assert "Enregistrer les règles" in body
    assert "hammering_login_enabled" in body
    assert "unknown_host_enabled" in body
    assert "Hôtes inconnus" in body
    assert "successful_login_enabled" in body
    assert "rate_limit_enabled" in body
    assert "rate_limit_login_enabled" in body
    assert "Rate limit (429)" in body
    assert body.count('action="/admin/security/banning/add"') == 1
    assert body.count('action="/admin/security/allowlist/add"') == 1
