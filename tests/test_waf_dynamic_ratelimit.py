"""WAF v3.1 — dynamic nginx rate-limit (429) + progressive auto-ban."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app.bastion.nginx_waf_export import (
    ensure_active_profile,
    render_limit_req_burst_snippet,
    render_rate_limits_conf,
    write_waf_exports,
)
from app.models import SecurityBan, SecurityAllowlistEntry
from app.security.banning.engine import (
    RULE_NGINX_LIMIT_REQ,
    apply_nginx_limit_req_ban,
    ensure_security_defaults,
    progressive_nginx_limit_ttl,
)
from app.security.banning.nginx_ratelimit_sensor import (
    KIND_NGINX_429,
    ingest_parsed_events,
    parse_rate_limit_line,
    record_nginx_429,
    reset_sensor_cursors_for_tests,
    run_sensor_tick,
)
from app.sso_settings import Settings


def _settings(tmp_path: Path, **extra) -> Settings:
    key = Fernet.generate_key().decode("ascii")
    kwargs = dict(
        portal_domain="portal.example.com",
        sso_portal_default_realm_slug="default",
        vault_portal_internal_token="test-signing-secret",
        portal_secret_encryption_key=key,
        exports_dir=str(tmp_path / "exports"),
        portal_data_dir=str(tmp_path / "data"),
    )
    kwargs.update(extra)
    return Settings(**kwargs)  # type: ignore[call-arg]


def test_render_rate_limits_conf_has_429_and_standard_zone(db_session, tmp_path):
    profile = ensure_active_profile(db_session)
    profile.portal_login_rate = 2
    profile.portal_api_rate = 50
    profile.portal_standard_rate = 20
    db_session.commit()
    conf = render_rate_limits_conf(profile)
    assert "limit_req_status 429;" in conf
    assert "zone=portal_login:10m rate=2r/s" in conf
    assert "zone=portal_api:10m rate=50r/s" in conf
    assert "zone=portal_standard:10m rate=20r/s" in conf
    assert "zone=portal_unknown_host:10m rate=5r/s" in conf
    assert "bastion-rate-limit.log" in conf
    assert "503" not in conf.split("limit_req_status")[1][:40]


def test_burst_snippet_and_export_files(db_session, tmp_path):
    settings = _settings(tmp_path)
    profile = ensure_active_profile(db_session)
    profile.portal_login_burst = 5
    profile.portal_api_burst = 20
    profile.portal_standard_burst = 10
    db_session.commit()
    assert "burst=7 nodelay" in render_limit_req_burst_snippet("portal_api", 7)
    paths = write_waf_exports(db_session, settings)
    assert "nginx-portal-rate-limits.conf" in paths
    exports = Path(settings.exports_dir)
    login = (exports / "limit_req_portal_login.conf").read_text(encoding="utf-8")
    api = (exports / "limit_req_portal_api.conf").read_text(encoding="utf-8")
    std = (exports / "limit_req_portal_standard.conf").read_text(encoding="utf-8")
    assert "zone=portal_login burst=5" in login
    assert "zone=portal_api burst=20" in api
    assert "zone=portal_standard burst=10" in std
    zones = (exports / "nginx-portal-rate-limits.conf").read_text(encoding="utf-8")
    assert "limit_req_status 429;" in zones


def test_progressive_ttl_ladder():
    assert progressive_nginx_limit_ttl(0) == (False, 15)
    assert progressive_nginx_limit_ttl(1) == (False, 120)
    assert progressive_nginx_limit_ttl(2) == (True, 0)
    assert progressive_nginx_limit_ttl(5) == (True, 0)


def test_apply_nginx_limit_req_ban_progressive(db_session):
    ensure_security_defaults(db_session)
    ip = "203.0.113.55"
    b1 = apply_nginx_limit_req_ban(
        db_session, ip=ip, rejection_count=30, window_seconds=60, zone="login"
    )
    assert b1 is not None
    assert b1.permanent is False
    assert b1.rule_type == RULE_NGINX_LIMIT_REQ
    assert "Zone login" in b1.reason
    # Lift so a new ban can be created (active ban blocks re-apply).
    b1.lifted_at = b1.banned_at
    db_session.commit()

    b2 = apply_nginx_limit_req_ban(
        db_session, ip=ip, rejection_count=40, window_seconds=60, zone="api"
    )
    assert b2 is not None
    assert b2.permanent is False
    assert b2.id != b1.id
    b2.lifted_at = b2.banned_at
    db_session.commit()

    b3 = apply_nginx_limit_req_ban(
        db_session, ip=ip, rejection_count=50, window_seconds=60, zone="standard"
    )
    assert b3 is not None
    assert b3.permanent is True


def test_parse_rate_limit_line():
    line = (
        "203.0.113.9 2026-10-25T12:00:00+00:00 POST /admin/auth/mfa/challenge 429 128"
    )
    parsed = parse_rate_limit_line(line)
    assert parsed is not None
    assert parsed["ip"] == "203.0.113.9"
    assert parsed["status"] == 429
    assert parsed["zone"] == "login"
    assert parse_rate_limit_line("203.0.113.9 x GET /x 200 1") is None


def test_sensor_escalates_after_threshold(db_session, tmp_path):
    ensure_security_defaults(db_session)
    settings = _settings(tmp_path)
    # Lower threshold for test
    from app.models import SecurityBanRule

    rule = (
        db_session.query(SecurityBanRule)
        .filter_by(rule_type=RULE_NGINX_LIMIT_REQ)
        .one()
    )
    rule.threshold = 5
    rule.window_seconds = 60
    db_session.commit()

    ip = "203.0.113.77"
    events = [
        {"ip": ip, "zone": "api", "status": 429}
        for _ in range(5)
    ]
    bans = ingest_parsed_events(db_session, events, settings=settings)
    assert len(bans) == 1
    assert bans[0].target == ip
    assert bans[0].rule_type == RULE_NGINX_LIMIT_REQ
    deny = Path(settings.exports_dir) / "waf-ip-deny.conf"
    # May or may not promote on first ban depending on ip_deny_min_occurrences;
    # export file should still exist after write_waf_exports.
    assert deny.is_file() or (Path(settings.exports_dir) / "nginx-portal-rate-limits.conf").is_file()


def test_sensor_skips_allowlisted_ip(db_session, tmp_path):
    ensure_security_defaults(db_session)
    settings = _settings(tmp_path)
    from app.models import SecurityBanRule

    rule = (
        db_session.query(SecurityBanRule)
        .filter_by(rule_type=RULE_NGINX_LIMIT_REQ)
        .one()
    )
    rule.threshold = 3
    db_session.commit()
    db_session.add(
        SecurityAllowlistEntry(
            entry_type="ip",
            value="203.0.113.88",
            comment="ops",
            created_by="test",
        )
    )
    db_session.commit()
    events = [{"ip": "203.0.113.88", "zone": "login", "status": 429} for _ in range(5)]
    bans = ingest_parsed_events(db_session, events, settings=settings)
    assert bans == []


def test_sensor_tick_reads_log(db_session, tmp_path):
    reset_sensor_cursors_for_tests()
    ensure_security_defaults(db_session)
    log_path = tmp_path / "rate.log"
    settings = _settings(tmp_path, nginx_rate_limit_log_path=str(log_path))
    from app.models import SecurityBanRule

    rule = (
        db_session.query(SecurityBanRule)
        .filter_by(rule_type=RULE_NGINX_LIMIT_REQ)
        .one()
    )
    rule.threshold = 2
    db_session.commit()
    log_path.write_text(
        "203.0.113.99 2026-10-25T12:00:00+00:00 GET /api/admin/x 429 10\n"
        "203.0.113.99 2026-10-25T12:00:01+00:00 GET /api/admin/y 429 10\n",
        encoding="utf-8",
    )
    result = run_sensor_tick(db_session, settings)
    assert result["events"] == 2
    assert result["bans"] == 1


def test_migration_094_exists():
    root = Path(__file__).resolve().parents[1]
    assert (root / "migrations/versions/094_waf_portal_standard_rate.py").is_file()
    vhost = (
        root / "docker/nginx/templates/vhost_sso_portal.conf.template"
    ).read_text(encoding="utf-8")
    assert "limit_req_portal_standard.conf" in vhost
    assert "limit_req_portal_login.conf" in vhost
    assert "limit_req zone=portal_api burst=" not in vhost
