"""Tests for WAF readability (lot 4)."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.bastion.nginx_waf_export import MODE_OFF, MODE_ON, MODE_DETECTION
from app.bastion.waf_readability import (
    UNKNOWN_HOST_FEED_RULE_LABEL,
    build_attack_controls,
    build_efficiency_panel,
    build_executive_summary,
    build_protection_layers,
    build_protection_verdict,
    build_unknown_host_panel,
    _apply_feed_target,
    _enrich_feed_source,
    _event_severity,
    _resolve_vhost_family,
)
from app.bastion.pending_host_service import record_unknown_host
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


def test_build_unknown_host_panel_counts_pending_hosts(db_session: Session):
    record_unknown_host(
        db_session,
        hostname="ar-systems.fr",
        client_ip="34.155.98.34",
        uri="/api/v2/settings",
        user_agent="PerplexityBot/1.0",
    )
    record_unknown_host(
        db_session,
        hostname="ar-systems.fr",
        client_ip="34.155.98.34",
        uri="/robots.txt",
        user_agent="PerplexityBot/1.0",
    )
    panel = build_unknown_host_panel(db_session, hours=24)
    assert panel["hits_24h"] >= 2
    assert len(panel["top_ips"]) >= 1
    assert panel["top_ips"][0]["ip"] == "34.155.98.34"


def test_build_attack_controls_merges_unknown_host(db_session: Session):
    settings = Settings(
        portal_domain="portal.example.fr",
        exports_dir="/tmp/waf-test",
    )  # type: ignore[call-arg]
    record_unknown_host(
        db_session,
        hostname="evil.example",
        client_ip="198.51.100.9",
        uri="/",
        user_agent="scanner",
    )
    controls = build_attack_controls(settings, db=db_session)
    assert controls["present"] is True
    assert any(a.get("source") == "unknown_host" for a in controls["recent"])
    assert any(
        a.get("ip") == "198.51.100.9" for a in controls["top_attackers"]
    )


def test_build_executive_summary_four_kpis(db_session: Session):
    settings = Settings(
        portal_domain="portal.example.fr",
        exports_dir="/tmp/waf-exec",
    )  # type: ignore[call-arg]
    active = {"verifiable": True, "aggregate_mode": "on", "families": {"portal": {"sec_rule_engine": "on"}}}
    efficiency = {
        "present": True,
        "inspected": 100,
        "blocks": 5,
        "critical": 1,
        "status": "ok",
    }
    ac = {"present": False, "critical_24h": 0}
    unknown = {"present": True, "hits_24h": 12}
    layers = [{"alert": False}]
    summary = build_executive_summary(settings, active, efficiency, ac, unknown, layers)
    assert summary["inspected"] == 100
    assert summary["blocks"] == 5
    assert 0 <= summary["health_score"] <= 100
    assert "health_gauge_svg" in summary
    assert "health_breakdown" in summary
    assert summary["live_suspicious"] >= 12


def test_health_score_breakdown_filtrage_alert():
    settings = Settings(portal_domain="portal.example.fr", exports_dir="/tmp/waf-exec")  # type: ignore[call-arg]
    active = {"verifiable": True, "aggregate_mode": "on", "families": {"portal": {"sec_rule_engine": "on"}}}
    efficiency = {"present": True, "inspected": 100, "blocks": 0, "critical": 0, "status": "ok"}
    layers = [
        {
            "name": "Filtrage d'hôtes",
            "alert": True,
            "detail": "500 refus / 24 h (hôtes non enregistrés)",
        }
    ]
    summary = build_executive_summary(settings, active, efficiency, {}, {"present": True}, layers)
    assert summary["health_score"] == 92
    assert len(summary["health_breakdown"]) == 1
    assert summary["health_breakdown"][0]["points"] == -8


def test_apply_feed_target_unknown_host_uses_ip_not_reverse_dns():
    row = {
        "source": "unknown_host",
        "host": "lm0ntsouris-657-1-66-85.w80-11.abo.wanadoo.fr",
        "uri": "/simple.php",
        "client_ip": "86.65.1.85",
    }
    _apply_feed_target(row)
    assert row["target_display"] == "86.65.1.85/simple.php"
    assert "wanadoo" in row["target_title"]


def test_unknown_host_feed_has_descriptive_rule_label(db_session: Session):
    record_unknown_host(
        db_session,
        hostname="scanner.evil.example",
        uri="/robots.php",
        client_ip="20.151.129.194",
    )
    panel = build_unknown_host_panel(db_session, hours=24)
    assert panel["recent"]
    row = panel["recent"][0]
    assert row["rule_label"] == UNKNOWN_HOST_FEED_RULE_LABEL
    assert row["rule_title"]
    assert _event_severity({**row, "blocked": True}) == "medium"


def test_enrich_feed_source_marks_modsecurity_and_subdomain(db_session: Session):
    from app.models import App

    settings = Settings(portal_domain="portal.example.fr")  # type: ignore[call-arg]
    db_session.add(
        App(
            slug="dolibarr",
            label="Dolibarr",
            public_fqdn="dolibarr.example.fr",
            access_mode="subdomain_proxy",
            enabled=True,
            upstream_url="http://127.0.0.1:8080",
        )
    )
    db_session.commit()
    row = {
        "source": "crs",
        "host": "dolibarr.example.fr",
        "blocked": True,
    }
    _enrich_feed_source(row, settings=settings, db=db_session)
    assert row["source_kind"] == "modsecurity"
    assert row["source_label"] == "CRS"
    assert row["vhost_family"] == "subdomain"
    assert row["vhost_family_label"] == "Sous-domaine"


def test_resolve_vhost_family_portal_host():
    settings = Settings(portal_domain="portal.example.fr")  # type: ignore[call-arg]
    assert _resolve_vhost_family("portal.example.fr", settings, None) == "portal"
    assert _resolve_vhost_family("auth.portal.example.fr", settings, None) == "portal"
