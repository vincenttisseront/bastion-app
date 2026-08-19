"""Tests for ModSecurity audit log aggregator."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from app.bastion.modsec_audit_aggregator import (
    read_audit_summary,
    resolve_modsec_audit_log_path,
    run_aggregation,
)
from app.sso_settings import Settings


def _sample_audit_line(*, rule_id: str = "942100", host: str = "portal.example.com") -> str:
    payload = {
        "transaction": {
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
    assert len(w24["top_rules"]) >= 1

    read_back = read_audit_summary(settings)
    assert read_back["present"] is True
    assert read_back["windows"]["24h"]["inspected"] == 2


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
