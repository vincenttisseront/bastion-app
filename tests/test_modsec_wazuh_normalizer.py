"""Unit tests for ansible role file modsec-wazuh-normalizer (no Ansible required)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    ROOT
    / "ansible"
    / "roles"
    / "modsec_wazuh_normalizer"
    / "files"
    / "modsec-wazuh-normalizer.py"
)


@pytest.fixture(scope="module")
def norm():
    spec = importlib.util.spec_from_file_location("modsec_wazuh_normalizer", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _audit(
    *,
    rule_id: str = "942100",
    host: str = "portal.ar-systems.fr",
    http_code: int = 403,
    uri: str = "/admin/x?token=secret",
    engine: str = "On",
    message: str = "SQL Injection Attack Detected",
) -> dict:
    return {
        "transaction": {
            "client_ip": "203.0.113.10",
            "client_port": 54321,
            "time_stamp": "2026-08-26T12:00:00+00:00",
            "unique_id": "abc-123",
            "request": {
                "method": "GET",
                "uri": uri,
                "headers": {"Host": host, "Cookie": "session=deadbeef"},
            },
            "response": {"http_code": http_code},
            "producer": {"secrules_engine": engine},
            "messages": [
                {
                    "message": message + " Matched Data: SELECT found within ARGS:q",
                    "details": {
                        "ruleId": rule_id,
                        "severity": "2",
                        "phase": "2",
                        "tags": ["OWASP_CRS", "attack-sqli"],
                        "file": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
                        "line": "10",
                        "data": "Matched Data: SELECT found within ARGS:q",
                    },
                }
            ],
        }
    }


def test_blocked_event_schema(norm):
    events = norm.normalize_events(
        _audit(), max_string=1024, max_tags=32, exclude_loopback=True
    )
    assert len(events) == 1
    ev = events[0]
    assert ev["integration"] == "bastion_modsecurity"
    assert ev["event_code"] == "BST-WAF-2001"
    assert ev["event_name"] == "MODSECURITY_REQUEST_BLOCKED"
    assert ev["outcome"] == "blocked"
    assert ev["blocked"] is True
    assert ev["rule_family"] == "sqli"
    assert ev["uri_path"] == "/admin/x"
    assert "token" not in ev["uri_path"]
    assert "deadbeef" not in json.dumps(ev)
    assert "Matched Data: [REDACTED]" in ev["rule_message"]
    assert "SELECT found" not in json.dumps(ev)


def test_detection_only_non_block(norm):
    events = norm.normalize_events(
        _audit(http_code=200, engine="DetectionOnly", rule_id="941100"),
        max_string=1024,
        max_tags=32,
        exclude_loopback=True,
    )
    assert len(events) == 1
    ev = events[0]
    assert ev["event_code"] == "BST-WAF-1001"
    assert ev["outcome"] == "detected"
    assert ev["detection_only"] is True
    assert ev["rule_family"] == "xss"


def test_exclude_loopback_host(norm):
    events = norm.normalize_events(
        _audit(host="127.0.0.1:8080", rule_id="920350"),
        max_string=1024,
        max_tags=32,
        exclude_loopback=True,
    )
    assert events == []


def test_rule_families(norm):
    assert norm.rule_family("949110") == "anomaly_score_block"
    assert norm.rule_family("920350") == "protocol"
    assert norm.rule_family("913100") == "scanner"
    assert norm.rule_family("999999") == "other"


def test_root_level_messages(norm):
    payload = {
        "transaction": {
            "client_ip": "198.51.100.1",
            "request": {"method": "POST", "uri": "/x", "headers": {"Host": "a.example"}},
            "response": {"http_code": 200},
            "producer": {"secrules_engine": "On"},
        },
        "messages": [
            {
                "message": "scan",
                "details": {"ruleId": "913100", "severity": "2", "phase": "1"},
            }
        ],
    }
    events = norm.normalize_events(
        payload, max_string=256, max_tags=8, exclude_loopback=True
    )
    assert len(events) == 1
    assert events[0]["rule_id"] == "913100"


def test_start_at_end_no_replay(norm, tmp_path: Path):
    source = tmp_path / "modsec_audit.log"
    output = tmp_path / "out.jsonl"
    state_path = tmp_path / "state.json"
    line = json.dumps(_audit()) + "\n"
    source.write_text(line, encoding="utf-8")

    state = norm.State(state_path)
    deduper = norm.Deduper(max_items=100, ttl_seconds=60)
    n = norm.run_once_file(
        source,
        output,
        state,
        start_at_end=True,
        max_string=1024,
        max_tags=32,
        exclude_loopback=True,
        deduper=deduper,
    )
    assert n == 0
    assert not output.exists() or output.read_text(encoding="utf-8") == ""

    # New event after init must be written
    source.write_text(line + json.dumps(_audit(rule_id="930100")) + "\n", encoding="utf-8")
    n2 = norm.run_once_file(
        source,
        output,
        state,
        start_at_end=True,
        max_string=1024,
        max_tags=32,
        exclude_loopback=True,
        deduper=deduper,
    )
    assert n2 >= 1
    body = output.read_text(encoding="utf-8")
    assert "930100" in body
