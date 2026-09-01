"""Tests for ModSecurity audit log aggregator."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from app.bastion.modsec_audit_aggregator import (
    build_rule_chain,
    extract_modsec_matched_target,
    format_rule_chain_display,
    is_audit_noise_event,
    is_crs_detection_rule_id,
    pick_primary_rule_id,
    read_audit_summary,
    resolve_modsec_audit_log_path,
    run_aggregation,
)
from app.sso_settings import Settings


def _sample_audit_line(
    *,
    rule_id: str = "942100",
    host: str = "portal.example.com",
    client_ip: str = "203.0.113.10",
    uri: str = "/api/test",
    matched_data: str | None = None,
    extra_messages: list[dict] | None = None,
) -> str:
    details: dict = {"ruleId": rule_id, "severity": "2"}
    message = "SQL Injection Attack Detected"
    if matched_data:
        details["data"] = matched_data
        message = f"{message} {matched_data}"
    messages = [
        {
            "message": message,
            "details": details,
        }
    ]
    if extra_messages:
        messages.extend(extra_messages)
    payload = {
        "transaction": {
            "client_ip": client_ip,
            "time_stamp": datetime.now(timezone.utc).isoformat(),
            "request": {
                "uri": uri,
                "headers": {"Host": host},
            },
            "response": {"http_code": 403},
            "messages": messages,
        }
    }
    return json.dumps(payload)


def test_pick_primary_rule_id_prefers_detection_over_949110():
    assert pick_primary_rule_id(["949110", "942100"]) == "942100"
    assert pick_primary_rule_id(["942100", "949110"]) == "942100"
    assert pick_primary_rule_id(["949110"]) == "949110"
    assert pick_primary_rule_id([]) == "—"


def test_build_rule_chain_dedupes_and_labels():
    chain = build_rule_chain(["942100", "949110", "942100"])
    assert [c["rule_id"] for c in chain] == ["942100", "949110"]
    assert chain[0]["label"] == "Injection SQL (libinjection)"
    display = format_rule_chain_display(chain)
    assert "942100" in display
    assert "949110" in display
    assert "→" in display


def test_aggregator_primary_rule_and_chain_with_anomaly_block(tmp_path: Path):
    logs = tmp_path / "nginx-logs"
    logs.mkdir()
    log_file = logs / "modsec_audit.log"
    log_file.write_text(
        _sample_audit_line(
            rule_id="942100",
            extra_messages=[
                {
                    "message": "Inbound Anomaly Score Exceeded (Total Score: 5)",
                    "details": {"ruleId": "949110", "severity": "0"},
                }
            ],
        )
        + "\n",
        encoding="utf-8",
    )
    settings = Settings(
        environment="test",
        database_url="sqlite://",
        nginx_app_logs_dir=str(logs),
    )
    summary = run_aggregation(settings)
    ev = summary["recent_events"][-1]
    assert ev["rule_id"] == "942100"
    assert ev["all_rule_ids"] == ["942100", "949110"]
    assert [c["rule_id"] for c in ev["rule_chain"]] == ["942100", "949110"]
    assert "942100" in ev["rule_chain_display"]
    assert "949110" in ev["rule_chain_display"]


def test_is_crs_detection_rule_id():
    assert is_crs_detection_rule_id("942100") is True
    assert is_crs_detection_rule_id("949110") is False
    assert is_crs_detection_rule_id("913100") is True


def test_rule_label_covers_common_protocol_and_lfi_ids():
    from app.bastion.modsec_audit_aggregator import rule_label

    assert rule_label("920450") == "En-tête HTTP restreint"
    assert rule_label("930130") == "Accès fichier restreint (LFI)"
    assert rule_label("920600") == "Accept charset illégal"
    assert rule_label("920440") == "Extension d'URL restreinte"
    assert "Règle CRS" not in rule_label("920450")


def test_extract_modsec_matched_target():
    kind, name = extract_modsec_matched_target(
        'Matched Data: UNION SELECT found within ARGS:search_term'
    )
    assert kind == "args"
    assert name == "search_term"
    # Never return the payload value
    assert "UNION" not in (name or "")

    kind2, name2 = extract_modsec_matched_target(
        "Matched Data: x within REQUEST_COOKIES:session_id"
    )
    assert kind2 == "cookies"
    assert name2 == "session_id"

    kind3, name3 = extract_modsec_matched_target("no match here")
    assert kind3 is None and name3 is None


def test_aggregator_captures_matched_target(tmp_path: Path):
    logs = tmp_path / "nginx-logs"
    logs.mkdir()
    log_file = logs / "modsec_audit.log"
    log_file.write_text(
        _sample_audit_line(
            uri="/api/v1/users",
            matched_data='Matched Data: UNION SELECT found within ARGS:search_term',
        )
        + "\n",
        encoding="utf-8",
    )
    settings = Settings(
        environment="test",
        database_url="sqlite://",
        nginx_app_logs_dir=str(logs),
    )
    summary = run_aggregation(settings)
    ev = summary["recent_events"][-1]
    assert ev["matched_scope_kind"] == "args"
    assert ev["matched_target_name"] == "search_term"
    assert "UNION" not in json.dumps(ev)


def test_aggregator_counts_detections(tmp_path: Path):
    logs = tmp_path / "nginx-logs"
    logs.mkdir()
    log_file = logs / "modsec_audit.log"
    log_file.write_text(
        _sample_audit_line() + "\n" + _sample_audit_line(rule_id="941100") + "\n",
        encoding="utf-8",
    )

    settings = Settings(
        environment="test",
        database_url="sqlite://",
        nginx_app_logs_dir=str(logs),
    )

    summary = run_aggregation(settings)
    assert summary["log_available"] is True
    w24 = summary["windows"]["24h"]
    assert w24["inspected"] == 2
    assert w24["detections"] == 2
    assert w24["blocks"] == 2
    assert w24["critical"] == 2
    assert len(w24["top_rules"]) >= 1
    assert w24["top_attackers"][0]["ip"] == "203.0.113.10"
    assert w24["top_attackers"][0]["count"] == 2
    assert summary["recent_events"][-1]["client_ip"] == "203.0.113.10"
    assert summary["recent_events"][-1]["critical"] is True

    read_back = read_audit_summary(settings)
    assert read_back["present"] is True
    assert read_back["windows"]["24h"]["inspected"] == 2


def test_aggregator_skips_loopback_host_noise(tmp_path: Path):
    """Host 127.0.0.1 / :8080 is health-smoke noise (CRS 920350), not attack signal."""
    logs = tmp_path / "nginx-logs"
    logs.mkdir()
    log_file = logs / "modsec_audit.log"
    log_file.write_text(
        "\n".join(
            [
                _sample_audit_line(rule_id="920350", host="127.0.0.1"),
                _sample_audit_line(rule_id="920350", host="127.0.0.1:8080"),
                _sample_audit_line(rule_id="920350", host="localhost"),
                _sample_audit_line(
                    rule_id="942100", host="portal.ar-systems.fr", client_ip="198.51.100.9"
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    settings = Settings(
        environment="test", database_url="sqlite://", nginx_app_logs_dir=str(logs)
    )
    summary = run_aggregation(settings)
    w24 = summary["windows"]["24h"]
    assert w24["inspected"] == 1
    assert w24["detections"] == 1
    assert w24["top_hosts"] == [{"host": "portal.ar-systems.fr", "count": 1}]
    assert w24["top_rules"][0]["rule_id"] == "942100"
    assert all(
        not str(h.get("host", "")).startswith("127.") for h in w24["top_hosts"]
    )


def test_aggregator_skips_loopback_client_ip_smoke(tmp_path: Path):
    """CRS smoke from docker01: Host=portal FQDN, client_ip=127.0.0.1 — not attack signal."""
    logs = tmp_path / "nginx-logs"
    logs.mkdir()
    log_file = logs / "modsec_audit.log"
    log_file.write_text(
        "\n".join(
            [
                _sample_audit_line(
                    rule_id="942180",
                    host="portal.ar-systems.fr",
                    client_ip="127.0.0.1",
                ),
                _sample_audit_line(
                    rule_id="942100",
                    host="portal.ar-systems.fr",
                    client_ip="198.51.100.9",
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    settings = Settings(
        environment="test", database_url="sqlite://", nginx_app_logs_dir=str(logs)
    )
    summary = run_aggregation(settings)
    w24 = summary["windows"]["24h"]
    assert w24["inspected"] == 1
    assert w24["detections"] == 1
    assert w24["top_attackers"] == [{"ip": "198.51.100.9", "count": 1}]
    assert all(e["client_ip"] != "127.0.0.1" for e in summary["recent_events"])
    assert is_audit_noise_event(
        {"host": "portal.ar-systems.fr", "client_ip": "127.0.0.1"}
    )


def test_rotation_resets_offset_without_double_count(tmp_path: Path):
    logs = tmp_path / "nginx-logs"
    logs.mkdir()
    log_file = logs / "modsec_audit.log"
    log_file.write_text(_sample_audit_line() + "\n", encoding="utf-8")

    settings = Settings(
        environment="test", database_url="sqlite://", nginx_app_logs_dir=str(logs)
    )
    run_aggregation(settings)

    log_file.unlink()
    log_file.write_text(_sample_audit_line(rule_id="930100") + "\n", encoding="utf-8")
    summary = run_aggregation(settings)
    assert summary["windows"]["24h"]["inspected"] == 2


def test_read_summary_unavailable_when_no_log(tmp_path: Path):
    settings = Settings(
        environment="test",
        database_url="sqlite://",
        nginx_app_logs_dir=str(tmp_path / "missing"),
    )
    out = read_audit_summary(settings)
    assert out["present"] is False
