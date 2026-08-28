"""Tests for ModSecurity audit log aggregator."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from app.bastion.modsec_audit_aggregator import (
    is_audit_noise_event,
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
) -> str:
    payload = {
        "transaction": {
            "client_ip": client_ip,
            "time_stamp": datetime.now(timezone.utc).isoformat(),
            "request": {
                "uri": "/api/test",
                "headers": {"Host": host},
            },
            "response": {"http_code": 403},
            "messages": [
                {
                    "message": "SQL Injection Attack Detected",
                    "details": {"ruleId": rule_id, "severity": "2"},
                }
            ],
        }
    }
    return json.dumps(payload)


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
