"""Promotion readiness + virtual-patch pack modes + ModSecurity page."""

from __future__ import annotations

from pathlib import Path

from app.bastion.nginx_waf_export import render_virtual_patches_enabled
from app.bastion.waf_promotion import evaluate_promotion_readiness
from app.bastion.waf_virtual_patches import (
    PACK_MODE_DETECTION,
    PACK_MODE_OFF,
    PACK_MODE_ON,
    PACK_PHP2SHELL,
    build_audit_health,
    build_modsecurity_page,
    build_top_rules_live,
    build_virtual_patches_panel,
    pack_source_present,
    render_virtual_patches_enabled_conf,
    render_virtual_patches_enabled_conf_from_modes,
    set_profile_pack_mode,
)
from app.models import WafProfile
from app.sso_settings import Settings


def test_pack_source_present_rejects_path_traversal_and_finds_repo_confs():
    assert pack_source_present("bastion-virtual-patches.conf") is True
    assert pack_source_present("bastion-pack-wordpress-cms.conf") is True
    assert pack_source_present("../bastion-virtual-patches.conf") is False
    assert pack_source_present("missing-pack.conf") is False
    assert pack_source_present("") is False


def test_virtual_patches_conf_include_when_enabled():
    text = render_virtual_patches_enabled_conf(php2shell_enabled=True)
    assert "Include /etc/nginx/modsecurity/bastion-virtual-patches.conf" in text
    assert "ctl:ruleEngine=DetectionOnly" not in text


def test_virtual_patches_conf_stub_when_disabled():
    text = render_virtual_patches_enabled_conf(php2shell_enabled=False)
    assert "Include /etc/nginx/modsecurity/bastion-virtual-patches.conf" not in text
    assert "disabled" in text.lower()


def test_virtual_patches_conf_detection_updates_actions():
    text = render_virtual_patches_enabled_conf_from_modes(
        {PACK_PHP2SHELL: PACK_MODE_DETECTION}
    )
    assert "Include /etc/nginx/modsecurity/bastion-virtual-patches.conf" in text
    assert "ctl:ruleEngine=" not in text
    assert "SecRuleUpdateActionById 100096180" in text
    assert "SecRuleUpdateActionById 100096184" in text
    assert "pass,log,auditlog" in text
    include_idx = text.index(
        "Include /etc/nginx/modsecurity/bastion-virtual-patches.conf"
    )
    update_idx = text.index("SecRuleUpdateActionById 100096180")
    assert include_idx < update_idx


def test_render_virtual_patches_from_profile():
    profile = WafProfile(
        name="P", mode="on", patch_php2shell_enabled=False, patch_php2shell_mode="off"
    )
    text = render_virtual_patches_enabled(profile)
    assert "Include /etc/nginx/modsecurity/bastion-virtual-patches.conf" not in text


def test_set_profile_pack_mode_syncs_legacy_bool():
    profile = WafProfile(
        name="P", mode="on", patch_php2shell_enabled=True, patch_php2shell_mode="on"
    )
    set_profile_pack_mode(profile, PACK_PHP2SHELL, mode=PACK_MODE_DETECTION)
    assert profile.patch_php2shell_mode == PACK_MODE_DETECTION
    assert profile.patch_php2shell_enabled is True
    set_profile_pack_mode(profile, PACK_PHP2SHELL, mode=PACK_MODE_OFF)
    assert profile.patch_php2shell_enabled is False


def test_promotion_not_applicable_when_disarmed(tmp_path):
    settings = Settings(
        portal_domain="portal.example.com",
        exports_dir=str(tmp_path / "exports"),
    )  # type: ignore[call-arg]
    (tmp_path / "exports" / "modsecurity").mkdir(parents=True)
    panel = evaluate_promotion_readiness(settings, family="portal")
    assert panel["status"] == "not_applicable"
    assert panel["can_promote"] is False
    assert panel["auto_promote"] is False


def test_virtual_patches_panel_lists_php2shell(db_session):
    settings = Settings(
        portal_domain="portal.example.com",
        exports_dir="/tmp/waf-vp",
    )  # type: ignore[call-arg]
    profile = WafProfile(
        name="P", mode="on", patch_php2shell_enabled=True, patch_php2shell_mode="on"
    )
    panel = build_virtual_patches_panel(db_session, settings, profile)
    assert panel["packs"]
    assert panel["packs"][0]["id"] == "php2shell"
    assert panel["packs"][0]["enabled"] is True
    assert panel["packs"][0]["mode"] == PACK_MODE_ON


def test_modsecurity_page_engine_crs_and_packs(db_session, tmp_path):
    settings = Settings(
        portal_domain="portal.example.com",
        exports_dir=str(tmp_path / "exports"),
    )  # type: ignore[call-arg]
    (tmp_path / "exports" / "modsecurity").mkdir(parents=True)
    profile = WafProfile(
        name="P",
        mode="detection_only",
        paranoia_level=2,
        patch_php2shell_enabled=True,
        patch_php2shell_mode="detection",
    )
    page = build_modsecurity_page(
        db_session,
        settings,
        profile,
        active={},
        reactivation={"armed": True, "subdomain_armed": False},
        effective={"present": True, "virtual_packs": {"php2shell": "on"}},
    )
    assert page["packs_total"] >= 1
    php = next(p for p in page["packs"] if p["id"] == PACK_PHP2SHELL)
    assert php["mode"] == PACK_MODE_DETECTION
    assert php["deploy_pending"] is True
    assert page["any_deploy_pending"] is True
    assert php["toggleable"] is True
    assert php["source_present"] is True
    assert len(php["rules"]) == 5
    assert page["crs"]["paranoia"] == 2
    assert "audit_health" in page
    assert "top_rules" in page
    labels = {r["label"] for r in page["engine_rows"]}
    assert labels == {"Portal", "Subdomain", "Public"}


def test_build_top_rules_live_from_summary():
    summary = {
        "present": True,
        "windows": {
            "24h": {
                "top_rules": [
                    {"rule_id": "942100", "label": "SQLi", "count": 42},
                    {"rule_id": "100096180", "count": 3},
                ]
            }
        },
    }
    rows = build_top_rules_live(summary, limit=5)
    assert rows[0]["rule_id"] == "942100"
    assert rows[0]["count"] == 42
    assert rows[0]["severity"] == "high"
    assert rows[1]["rule_id"] == "100096180"
    assert rows[1]["severity"] == "critical"


def test_build_audit_health_missing(tmp_path, monkeypatch):
    settings = Settings(
        portal_domain="portal.example.com",
        exports_dir=str(tmp_path / "exports"),
    )  # type: ignore[call-arg]
    missing = tmp_path / "nginx-logs" / "waf-audit-summary.json"
    monkeypatch.setattr(
        "app.bastion.waf_virtual_patches.resolve_audit_summary_path",
        lambda _s: missing,
    )
    health = build_audit_health(settings, {"present": False})
    assert health["level"] == "red"


def test_build_audit_health_fresh_ok(tmp_path, monkeypatch):
    settings = Settings(
        portal_domain="portal.example.com",
        exports_dir=str(tmp_path / "exports"),
    )  # type: ignore[call-arg]
    path = tmp_path / "waf-audit-summary.json"
    path.write_text('{"present": true}\n', encoding="utf-8")
    monkeypatch.setattr(
        "app.bastion.waf_virtual_patches.resolve_audit_summary_path",
        lambda _s: path,
    )
    health = build_audit_health(settings, {"present": True}, traffic_active=True)
    assert health["level"] == "green"
    assert health["readable"] is True

