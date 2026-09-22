"""Tests for WAF readability."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.bastion.nginx_waf_export import MODE_OFF, MODE_ON, MODE_DETECTION
from app.bastion.waf_readability import (
    UNKNOWN_HOST_FEED_RULE_LABEL,
    build_attack_controls,
    build_efficiency_panel,
    build_efficiency_visuals,
    build_executive_summary,
    build_protection_layers,
    build_protection_verdict,
    build_quarantine_panel,
    build_threat_intel_visuals,
    build_unknown_host_panel,
    _apply_feed_target,
    _efficiency_zero_explanation,
    _enrich_feed_source,
    _event_severity,
    _resolve_vhost_family,
)
from app.bastion.pending_host_service import record_unknown_host
from app.models import SecurityBan, WafProfile
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


def test_threat_intel_owasp_rows_use_catalog_and_attach_events(tmp_path: Path):
    logs = tmp_path / "logs"
    logs.mkdir()
    summary = {
        "schema_version": 2,
        "generated_at": "2026-09-01T12:00:00+00:00",
        "log_available": True,
        "windows": {
            "24h": {
                "inspected": 10,
                "detections": 5,
                "blocks": 5,
                "critical": 1,
                "top_rules": [
                    {"rule_id": "920450", "label": "Règle CRS 920450", "count": 403},
                    {"rule_id": "930130", "label": "Règle CRS 930130", "count": 105},
                ],
            }
        },
        "series": {"24h": [{"label": "12h", "detections": 5, "inspected": 10}]},
        "recent_events": [
            {
                "timestamp": "2026-09-01T11:00:00+00:00",
                "client_ip": "203.0.113.9",
                "host": "portal.example.fr",
                "uri": "/df.php",
                "rule_id": "920450",
                "all_rule_ids": ["920450", "949110"],
                "blocked": True,
                "message": "HTTP header is restricted by policy",
            }
        ],
    }
    (logs / "waf-audit-summary.json").write_text(json.dumps(summary), encoding="utf-8")
    settings = Settings(
        environment="test", database_url="sqlite://", nginx_app_logs_dir=str(logs)
    )
    ti = build_threat_intel_visuals(
        settings,
        {"verifiable": True, "aggregate_mode": MODE_ON},
        {"present": True, "status": "ok"},
    )
    assert ti["top_rules"][0]["rule_id"] == "920450"
    assert ti["top_rules"][0]["label"] == "En-tête HTTP restreint"
    assert "Règle CRS" not in ti["top_rules"][0]["label"]
    assert ti["top_rules"][0]["events"]
    assert ti["top_rules"][0]["events"][0]["uri"] == "/df.php"
    assert ti["top_rules"][1]["label"] == "Accès fichier restreint (LFI)"


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
        hostname="unknown.example.com",
        client_ip="198.51.100.34",
        uri="/api/v2/settings",
        user_agent="PerplexityBot/1.0",
    )
    record_unknown_host(
        db_session,
        hostname="unknown.example.com",
        client_ip="198.51.100.34",
        uri="/robots.txt",
        user_agent="PerplexityBot/1.0",
    )
    panel = build_unknown_host_panel(db_session, hours=24)
    assert panel["hits_24h"] >= 2
    assert len(panel["top_ips"]) >= 1
    assert panel["top_ips"][0]["ip"] == "198.51.100.34"


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


def test_apply_feed_target_unknown_host_shows_refused_host():
    row = {
        "source": "unknown_host",
        "host": "203.0.113.10",
        "uri": "/wp-json/batch/v1",
        "client_ip": "93.123.109.163",
    }
    _apply_feed_target(row)
    assert row["target_display"] == "203.0.113.10/wp-json/batch/v1"
    assert "93.123.109.163" not in row["target_display"]
    assert "203.0.113.10" in row["target_title"]


def test_apply_feed_target_unknown_host_keeps_long_hostname():
    row = {
        "source": "unknown_host",
        "host": "lm0ntsouris-657-1-66-85.w80-11.abo.wanadoo.fr",
        "uri": "/simple.php",
        "client_ip": "86.65.1.85",
    }
    _apply_feed_target(row)
    assert row["target_display"].startswith("lm0ntsouris")
    assert "/simple.php" in row["target_display"]
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


def test_quarantine_panel_dedupes_ip_and_limits(db_session: Session):
    for _ in range(5):
        db_session.add(
            SecurityBan(
                target_type="ip",
                target="8.234.135.108",
                reason="rafale",
                rule_type="unknown_host_hammering",
                permanent=False,
                created_by="test",
            )
        )
    db_session.add(
        SecurityBan(
            target_type="ip",
            target="203.0.113.9",
            reason="manual",
            rule_type="manual",
            permanent=True,
            created_by="test",
        )
    )
    db_session.commit()
    panel = build_quarantine_panel(db_session, limit=8)
    assert panel["count"] == 2
    by_ip = {r["ip"]: r for r in panel["rows"]}
    assert by_ip["8.234.135.108"]["ban_count"] == 5
    assert panel["truncated"] is False


def test_efficiency_zero_explanation_by_mode():
    assert "arrêté" in _efficiency_zero_explanation(MODE_OFF)
    assert "audit" in _efficiency_zero_explanation(MODE_DETECTION).lower()
    assert "CRS" in _efficiency_zero_explanation(MODE_ON)


def test_build_efficiency_visuals_status_panels(tmp_path: Path):
    settings = Settings(
        environment="test",
        database_url="sqlite://",
        nginx_app_logs_dir=str(tmp_path),
    )
    unavailable = build_efficiency_visuals(
        settings,
        {"verifiable": True},
        {"present": False, "message": "missing", "resolution": "fix aggregator"},
    )
    assert unavailable["status"] == "unavailable"
    assert unavailable["detections_hourly_svg"]

    unverifiable = build_efficiency_visuals(
        settings,
        {"verifiable": False},
        {"present": True, "status": "ok"},
    )
    assert unverifiable["status"] == "unverifiable"


def test_feed_host_key_and_family_from_apps(db_session: Session):
    from app.bastion.waf_readability import _family_from_enabled_apps, _feed_host_key
    from app.models import App

    assert _feed_host_key("") == ""
    assert _feed_host_key("App.Example.com:443") == "app.example.com"
    db_session.add(
        App(
            slug="sub",
            label="Sub",
            enabled=True,
            public_fqdn="sub.example.com",
            access_mode="subdomain_proxy",
            upstream_url="http://10.0.0.10/",
        )
    )
    db_session.commit()
    assert _family_from_enabled_apps(db_session, "sub.example.com") == "subdomain"


def test_ip_deny_layer_states():
    from app.bastion.waf_readability import _ip_deny_layer

    promoted = _ip_deny_layer(
        promoted_ips=["198.51.100.1"], ip_ban_count=0, min_occurrences=3
    )
    assert promoted["state"] == "actif"
    assert promoted["css"] == "badge-ok"
    assert "1 IP promue" in promoted["detail"]

    quarantine = _ip_deny_layer(
        promoted_ips=[], ip_ban_count=2, min_occurrences=3
    )
    assert quarantine["state"] == "app seul"
    assert quarantine["css"] == "badge-warn"
    assert "2 IP en quarantaine" in quarantine["detail"]

    empty = _ip_deny_layer(promoted_ips=[], ip_ban_count=0, min_occurrences=3)
    assert empty["state"] == "aucune IP"
    assert empty["css"] == "badge-muted"


def test_reactivation_summary_text_variants():
    from app.bastion.waf_readability import _reactivation_summary_text

    both = _reactivation_summary_text(
        portal_armed=True, subdomain_armed=True, subdomain_already_on=False
    )
    assert "portail" in both.lower() or "Portal" in both or "DetectionOnly" in both

    portal_only = _reactivation_summary_text(
        portal_armed=True, subdomain_armed=False, subdomain_already_on=False
    )
    assert portal_only

    idle = _reactivation_summary_text(
        portal_armed=False, subdomain_armed=False, subdomain_already_on=False
    )
    assert idle


def test_matching_rule_events_filters_by_id():
    from app.bastion.waf_readability import _matching_rule_events

    recent = [
        {"rule_id": "941100", "all_rule_ids": ["941100"], "uri": "/a", "client_ip": "10.0.0.1"},
        {"rule_id": "942100", "all_rule_ids": ["942100", "941100"], "uri": "/b"},
        "skip-me",
    ]
    matched = _matching_rule_events(recent, "941100", limit=10)
    assert len(matched) == 2
    assert matched[0]["uri"] == "/b"
    assert matched[1]["uri"] == "/a"
