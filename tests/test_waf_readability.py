"""Tests for WAF readability (lot 4)."""

from __future__ import annotations

import json
from pathlib import Path

from app.bastion.nginx_waf_export import MODE_OFF, MODE_ON, MODE_DETECTION
from app.bastion.waf_readability import (
    build_efficiency_panel,
    build_protection_layers,
    build_protection_verdict,
)
from app.models import WafProfile
from app.security.banning.service import get_or_create_policy
from app.sso_settings import Settings


def test_verdict_inactive_when_engine_off():
    profile = WafProfile(name="P", mode=MODE_ON, anomaly_threshold=5)
    active = {
        "verifiable": True,
        "aggregate_mode": MODE_OFF,
        "engine_mode_generated_loaded": False,
    }
    v = build_protection_verdict(profile, active, export_pending=False, page="unified")
    assert v["level"] == "inactive"
    assert "INACTIVE" in v["title"]
    assert v["css"] == "alert-err"
    assert v["action_apply"] is False
    assert v["action_href"] == "#reactivation"
    assert v["mode_pilotable"] is False
    assert "Réactiver" in (v.get("action_label") or "") or "Réactivation" in (
        v.get("action_label") or ""
    )


def test_verdict_inactive_pilotable_offers_apply(tmp_path: Path):
    settings = Settings(
        portal_domain="portal.example.fr",
        exports_dir=str(tmp_path / "exports"),
        portal_data_dir=str(tmp_path / "data"),
        nginx_app_logs_dir=str(tmp_path / "nginx-logs"),
    )  # type: ignore[call-arg]
    arm = tmp_path / "exports" / "modsecurity" / "waf-engine-arm.json"
    arm.parent.mkdir(parents=True)
    arm.write_text('{"armed": true}', encoding="utf-8")

    profile = WafProfile(name="P", mode=MODE_ON, anomaly_threshold=5)
    active = {
        "verifiable": True,
        "aggregate_mode": MODE_OFF,
        "families": {"portal": {"sec_rule_engine": MODE_OFF}},
        "engine_mode_generated_loaded": True,
    }
    v = build_protection_verdict(
        profile, active, export_pending=False, settings=settings, page="unified"
    )
    assert v["level"] == "inactive"
    assert v["action_apply"] is True


def test_verdict_disarmed_suggests_reactivation_not_apply(tmp_path: Path):
    settings = Settings(
        portal_domain="portal.example.fr",
        exports_dir=str(tmp_path / "exports"),
        portal_data_dir=str(tmp_path / "data"),
        nginx_app_logs_dir=str(tmp_path / "nginx-logs"),
    )  # type: ignore[call-arg]
    arm = tmp_path / "exports" / "modsecurity" / "waf-engine-arm.json"
    arm.parent.mkdir(parents=True)
    arm.write_text('{"armed": false}', encoding="utf-8")

    profile = WafProfile(name="P", mode=MODE_DETECTION, anomaly_threshold=5)
    active = {
        "verifiable": True,
        "families": {"portal": {"sec_rule_engine": MODE_OFF}},
        "engine_mode_generated_loaded": True,
    }
    v = build_protection_verdict(
        profile, active, export_pending=False, settings=settings, page="unified"
    )
    assert v["level"] == "inactive"
    assert v.get("action_apply") is False
    assert v.get("action_href") == "#reactivation"
    assert "Appliquer seul" in v["message"]


def test_verdict_active_when_aligned():
    profile = WafProfile(name="P", mode=MODE_ON, anomaly_threshold=5)
    active = {
        "verifiable": True,
        "aggregate_mode": "mixed",
        "families": {"portal": {"sec_rule_engine": MODE_ON}},
        "engine_mode_generated_loaded": True,
    }
    v = build_protection_verdict(profile, active, export_pending=False)
    assert v["level"] == "active"
    assert v["css"] == "alert-ok"


def test_verdict_observe_when_portal_detection_only_despite_mixed_aggregate():
    profile = WafProfile(name="P", mode=MODE_DETECTION, anomaly_threshold=5)
    active = {
        "verifiable": True,
        "aggregate_mode": "mixed",
        "families": {
            "portal": {"sec_rule_engine": MODE_DETECTION},
            "subdomain": {"sec_rule_engine": MODE_OFF},
            "public": {"sec_rule_engine": MODE_OFF},
        },
        "engine_mode_generated_loaded": True,
    }
    v = build_protection_verdict(profile, active, export_pending=False, page="unified")
    assert v["level"] == "observe"
    assert "observation" in v["title"].lower()


def test_verdict_profile_on_nginx_detection_is_not_observe():
    profile = WafProfile(name="Production", mode=MODE_ON, anomaly_threshold=5)
    active = {
        "verifiable": True,
        "families": {"portal": {"sec_rule_engine": MODE_DETECTION}},
        "engine_mode_generated_loaded": True,
    }
    v = build_protection_verdict(profile, active, export_pending=False, page="unified")
    assert v["level"] == "mismatch"
    assert v["title"] == "Profil On — nginx encore en observation"
    assert v["action_apply"] is True


def test_diagnostic_no_mode_mismatch_when_portal_aligned_mixed_aggregate():
    from app.bastion.waf_readability import build_waf_diagnostic_export

    payload = build_waf_diagnostic_export(
        desired={"mode": MODE_DETECTION, "anomaly_threshold": 5, "profile_name": "Production"},
        generated={"present": True, "mode": MODE_DETECTION, "path": "/tmp/export.json"},
        active={
            "verifiable": True,
            "aggregate_mode": "mixed",
            "aggregate_threshold": 5,
            "families": {
                "portal": {"sec_rule_engine": MODE_DETECTION},
                "subdomain": {"sec_rule_engine": MODE_OFF},
            },
            "snapshot_path": "/tmp/snap.json",
        },
        pending_diffs=[],
        export_pending=False,
        control_effect={"mode": True, "anomaly_threshold": False},
        security_headers_panel={"present": False, "headers": []},
        diagnostic={"checks": [], "summary_path": "/tmp/summary.json"},
        verdict={"level": "observe", "title": "observe", "message": "ok"},
    )
    mode_mismatches = [m for m in payload["alignment"]["mismatches"] if m.get("field") == "mode"]
    assert mode_mismatches == []
    assert payload["actual"]["portal_mode"] == MODE_DETECTION


def test_efficiency_unavailable_without_summary(tmp_path: Path):
    settings = Settings(
        environment="test",
        database_url="sqlite://",
        nginx_app_logs_dir=str(tmp_path),
    )
    panel = build_efficiency_panel(
        settings, {"verifiable": True, "aggregate_mode": MODE_OFF}
    )
    assert panel["present"] is False


def test_efficiency_zero_explanation_when_engine_off(tmp_path: Path):
    logs = tmp_path / "logs"
    logs.mkdir()
    summary = {
        "schema_version": 1,
        "generated_at": "2026-08-19T12:00:00+00:00",
        "log_available": True,
        "windows": {
            "24h": {
                "inspected": 0,
                "detections": 0,
                "blocks": 0,
                "block_rate_pct": 0,
                "top_rules": [],
                "top_hosts": [],
            }
        },
    }
    (logs / "waf-audit-summary.json").write_text(json.dumps(summary), encoding="utf-8")
    settings = Settings(
        environment="test", database_url="sqlite://", nginx_app_logs_dir=str(logs)
    )
    panel = build_efficiency_panel(
        settings, {"verifiable": True, "aggregate_mode": MODE_OFF}
    )
    assert panel["present"] is True
    assert panel["inspected"] == 0
    assert panel["status"] == "measured_zero"
    assert "moteur est arrêté" in (panel.get("zero_explanation") or "")


def test_protection_layers_anti_bruteforce_alert_when_policy_disabled(db_session):
    profile = WafProfile(
        name="P",
        mode=MODE_ON,
        anomaly_threshold=5,
        portal_login_rate=3,
        portal_api_rate=30,
        ip_deny_min_occurrences=3,
    )
    policy = get_or_create_policy(db_session)
    policy.enabled = False
    db_session.commit()

    active = {"verifiable": True, "aggregate_mode": MODE_ON}
    layers = build_protection_layers(db_session, profile, active, {"present": True, "headers": []})
    anti = next(layer for layer in layers if layer["name"] == "Anti-bruteforce")
    assert anti["alert"] is True
    assert anti["css"] == "badge-err"
    assert "désactivé" in anti["state"]


def test_diagnostic_export_expected_vs_actual():
    from app.bastion.waf_readability import build_waf_diagnostic_export

    payload = build_waf_diagnostic_export(
        desired={"mode": "on", "anomaly_threshold": 5, "profile_name": "Production"},
        generated={"present": True, "mode": "on", "path": "/tmp/export.json"},
        active={
            "verifiable": True,
            "aggregate_mode": "off",
            "aggregate_threshold": 5,
            "families": {"portal": {"sec_rule_engine": "off"}},
            "snapshot_path": "/tmp/snap.json",
        },
        pending_diffs=[],
        export_pending=False,
        control_effect={"mode": False},
        security_headers_panel={"present": False, "headers": []},
        diagnostic={"checks": [], "summary_path": "/tmp/summary.json"},
        verdict={"level": "inactive", "title": "INACTIVE", "message": "off"},
    )
    assert payload["kind"] == "bastion-waf-diagnostic"
    assert payload["expected"]["profile"]["mode"] == "on"
    assert payload["actual"]["aggregate_mode"] == "off"
    assert any(m["field"] == "mode" for m in payload["alignment"]["mismatches"])
