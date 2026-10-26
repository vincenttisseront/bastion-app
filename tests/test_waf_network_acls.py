"""WAF network ACLs — allow/deny export + analytics KPIs."""

from __future__ import annotations

from pathlib import Path

from app.bastion.nginx_waf_export import (
    list_allowlist_ips,
    render_ip_allow_conf,
    render_ip_deny_conf,
    write_waf_exports,
)
from app.bastion.waf_analytics import build_waf_analytics_summary
from app.bastion import waf_config_drift as drift_mod
from app.bastion.waf_config_drift import build_waf_config_drift
from app.models import SecurityAllowlistEntry, SecurityBan, WafProfile
from app.security.banning.service import add_allowlist_entry
from app.sso_settings import Settings

ROOT = Path(__file__).resolve().parents[1]


def test_render_ip_allow_conf_sanitizes():
    text = render_ip_allow_conf(["10.0.0.0/8", "bad host", "2001:db8::1"])
    assert "allow 10.0.0.0/8;" in text
    assert "allow 2001:db8::1;" in text
    assert "bad host" in text  # commented skip
    assert "allow bad" not in text


def test_nginx_includes_allow_before_deny():
    text = (ROOT / "docker/nginx/nginx.conf").read_text(encoding="utf-8")
    allow_i = text.index("include /etc/nginx/includes/waf-ip-allow.conf;")
    deny_i = text.index("include /etc/nginx/includes/waf-ip-deny.conf;")
    assert allow_i < deny_i


def test_drift_catalog_includes_ip_allow():
    ids = {f["id"] for f in drift_mod._DRIFT_SPECS}
    assert "waf-ip-allow" in ids
    assert "waf-ip-deny" in ids


def test_write_exports_allow_and_deny(db_session, tmp_path):
    settings = Settings(
        environment="test",
        portal_domain="portal.example.com",
        exports_dir=str(tmp_path / "exports"),
        portal_data_dir=str(tmp_path / "data"),
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        breakglass_jwt_secret_fallback_enabled=True,
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    profile = WafProfile(
        name="ACL",
        mode="on",
        is_active=True,
        ip_deny_min_occurrences=1,
        patch_php2shell_mode="on",
    )
    db_session.add(profile)
    db_session.commit()
    add_allowlist_entry(
        db_session,
        entry_type="ip",
        value="10.10.0.0/16",
        comment="VPN lab",
        actor="admin@example.com",
    )
    db_session.add(
        SecurityBan(
            target_type="ip",
            target="203.0.113.50",
            reason="manual test",
            rule_type="manual",
            permanent=True,
        )
    )
    db_session.commit()

    write_waf_exports(db_session, settings)
    allow_path = tmp_path / "exports" / "waf-ip-allow.conf"
    deny_path = tmp_path / "exports" / "waf-ip-deny.conf"
    assert allow_path.is_file()
    assert "allow 10.10.0.0/16;" in allow_path.read_text(encoding="utf-8")
    assert "deny 203.0.113.50;" in deny_path.read_text(encoding="utf-8")
    assert list_allowlist_ips(db_session) == ["10.10.0.0/16"]

    drift = build_waf_config_drift(db_session, settings)
    by_id = {f["id"]: f for f in drift.get("files") or []}
    assert "waf-ip-allow" in by_id


def test_network_kpis_in_analytics(db_session, tmp_path):
    settings = Settings(
        environment="test",
        portal_domain="portal.example.com",
        exports_dir=str(tmp_path / "exports"),
        portal_data_dir=str(tmp_path / "data"),
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        breakglass_jwt_secret_fallback_enabled=True,
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    profile = WafProfile(name="ACL2", mode="on", is_active=True)
    db_session.add(profile)
    db_session.add(
        SecurityAllowlistEntry(
            entry_type="ip", value="192.168.0.0/16", comment="lab"
        )
    )
    db_session.add(
        SecurityBan(
            target_type="ip",
            target="198.51.100.9",
            reason="probe",
            permanent=False,
        )
    )
    db_session.commit()
    analytics = build_waf_analytics_summary(
        db_session,
        settings,
        profile,
        summary={"present": False},
        active={"verifiable": False},
    )
    net = analytics["network"]
    assert net["banned_ips_active"] >= 1
    assert net["allowlist_ips"] >= 1
    assert net["acl_rejections_instrumented"] is False
