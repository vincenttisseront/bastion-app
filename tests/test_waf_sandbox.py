"""WAF sandbox probe helpers + admin endpoint."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.bastion.waf_sandbox import (
    _extract_matched_rules,
    _is_disruptive_message,
    find_sandbox_audit_event,
    normalize_sandbox_uri,
    run_waf_sandbox,
)
from app.sso_settings import Settings


ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def test_normalize_sandbox_uri():
    assert normalize_sandbox_uri("login") == "/login"
    assert normalize_sandbox_uri("/admin/foo") == "/admin/foo"
    try:
        normalize_sandbox_uri("/__waf_sandbox/x")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_disruptive_message_detection():
    assert _is_disruptive_message(
        {"message": "Access denied with code 403", "details": {"ruleId": "942100"}}
    )
    assert _is_disruptive_message(
        {
            "message": "SQLi",
            "details": {"ruleId": "942100", "severity": 2, "actions": "deny"},
        }
    )
    assert not _is_disruptive_message(
        {
            "message": "Detection only notice",
            "details": {"ruleId": "913100", "severity": 0},
        }
    )


def test_extract_matched_rules_and_blocked_intent():
    tx = {
        "messages": [
            {
                "message": "SQL Injection Attack",
                "details": {
                    "ruleId": "942100",
                    "severity": 2,
                    "phase": 2,
                    "actions": "deny,status:403",
                },
            },
            {
                "message": "Scanner",
                "details": {"ruleId": "913100", "severity": 0, "phase": 1},
            },
        ]
    }
    rules = _extract_matched_rules(tx)
    assert [r["id"] for r in rules] == ["942100", "913100"]
    assert rules[0]["disruptive"] is True
    assert rules[1]["disruptive"] is False


def test_find_sandbox_audit_event(tmp_path: Path):
    sid = "11111111-2222-3333-4444-555555555555"
    log = tmp_path / "modsec_audit.log"
    event = {
        "transaction": {
            "request": {
                "uri": "/login",
                "headers": {"X-Bastion-Sandbox-Id": sid},
            },
            "messages": [
                {
                    "message": "denied",
                    "details": {
                        "ruleId": "100096180",
                        "severity": 2,
                        "actions": "deny",
                    },
                }
            ],
        }
    }
    log.write_text(json.dumps(event) + "\n", encoding="utf-8")
    found = find_sandbox_audit_event(log, sid, wait_sec=0.3)
    assert found is not None
    rules = _extract_matched_rules(found["transaction"])
    assert rules[0]["id"] == "100096180"


def test_run_waf_sandbox_correlates_mocked_probe(tmp_path: Path):
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
    logs = tmp_path / "data" / "nginx-logs"
    logs.mkdir(parents=True)

    class _Resp:
        status = 204

        def read(self, _n=0):
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_open(req, timeout=0):  # noqa: ARG001
        # urllib Request stores custom headers lowercased after the first letter.
        sid = req.get_header("X-bastion-sandbox-id")
        assert sid, "sandbox probe must send X-Bastion-Sandbox-Id"
        log = logs / "modsec_audit.log"
        log.write_text(
            json.dumps(
                {
                    "transaction": {
                        "request": {
                            "uri": "/login",
                            "headers": {"X-Bastion-Sandbox-Id": sid},
                        },
                        "messages": [
                            {
                                "message": "Access denied",
                                "details": {
                                    "ruleId": "942100",
                                    "severity": 2,
                                    "phase": 2,
                                    "actions": "deny",
                                },
                            }
                        ],
                    }
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return _Resp()

    with (
        patch(
            "app.bastion.waf_sandbox.resolve_modsec_audit_log_path",
            return_value=logs / "modsec_audit.log",
        ),
        patch("app.bastion.waf_sandbox._PROBE_OPENER") as opener,
        patch(
            "app.bastion.waf_sandbox.read_nginx_waf_reality",
            return_value={"verifiable": False},
        ),
        patch(
            "app.bastion.waf_sandbox.read_arm_state",
            return_value={"armed": True},
        ),
        patch(
            "app.bastion.waf_sandbox.build_sandbox_readiness",
            return_value={"warnings": [], "usable": True},
        ),
    ):
        opener.open.side_effect = fake_open
        result = run_waf_sandbox(
            settings,
            method="POST",
            uri="/login",
            body="q=1' OR '1'='1",
            content_type="application/x-www-form-urlencoded",
        )
    assert result["blocked_intent"] is True
    assert result["verdict"] == "blocked"
    assert result["matched_rules"][0]["id"] == "942100"
    assert result["probe"]["ok"] is True


def test_sandbox_endpoint(client: TestClient):
    fake = {
        "ok": True,
        "sandbox_id": "abc",
        "method": "GET",
        "uri": "/",
        "blocked_intent": False,
        "matched_rules": [],
        "verdict": "clean",
        "probe": {"ok": True, "status": 204},
        "audit_found": True,
        "readiness": {"warnings": []},
    }
    with patch(
        "app.bastion.waf_sandbox.run_waf_sandbox", return_value=fake
    ):
        resp = client.post(
            "/admin/security/waf/sandbox",
            headers=ADMIN_HEADERS,
            data={
                "method": "GET",
                "uri": "/",
                "body": "",
                "content_type": "text/plain",
            },
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["verdict"] == "clean"


def test_sandbox_endpoint_rejects_bad_uri(client: TestClient):
    with patch(
        "app.bastion.waf_sandbox.run_waf_sandbox",
        side_effect=ValueError("URI invalide"),
    ):
        resp = client.post(
            "/admin/security/waf/sandbox",
            headers=ADMIN_HEADERS,
            data={
                "method": "GET",
                "uri": "/__waf_sandbox/x",
                "body": "",
                "content_type": "text/plain",
            },
        )
    assert resp.status_code == 400
    assert resp.json()["ok"] is False
