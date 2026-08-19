"""Integration tests for /admin/security/protection (lot 5)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.bastion.nginx_waf_export import MODE_OFF, MODE_ON
from app.bastion.waf_readability import build_efficiency_panel, build_protection_layers
from app.models import WafProfile
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _write_snapshot(path: Path, *, mode: str = MODE_OFF) -> None:
    fam = {
        "family": "portal",
        "sec_rule_engine": mode,
        "anomaly_threshold": 5,
        "engine_mode_generated_loaded": False,
        "crs_setup_generated_loaded": False,
        "engine_file": "/etc/nginx/modsecurity/engine-portal.conf",
    }
    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "nginx_version": "nginx/1.30.4",
        "image_tag": "bastion-nginx:test",
        "nginx_t_ok": True,
        "families": {
            "portal": {**fam, "family": "portal"},
            "subdomain": {**fam, "family": "subdomain"},
            "public": {**fam, "family": "public"},
        },
        "aggregate_mode": mode,
        "aggregate_threshold": 5,
        "engine_mode_generated_loaded": False,
        "crs_setup_generated_loaded": False,
        "security_headers": {
            "path": "/etc/nginx/includes/security-headers.conf",
            "headers": [
                {"name": "Strict-Transport-Security", "value": "max-age=31536000"},
            ],
            "included_on_443": True,
            "no_duplicate_8080": True,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _patch_snapshot(tmp_path: Path, *, mode: str = MODE_OFF):
    snap = tmp_path / "nginx-waf-snapshot.json"
    _write_snapshot(snap, mode=mode)
    return patch(
        "app.bastion.nginx_waf_reality.resolve_nginx_waf_snapshot_path",
        return_value=snap,
    )


def _seed_profile(db_session: Session) -> None:
    db_session.add(
        WafProfile(
            name="Production",
            mode="on",
            anomaly_threshold=5,
            ip_deny_min_occurrences=3,
            is_active=True,
            created_by="test",
        )
    )
    db_session.commit()


def test_protection_page_requires_admin(client: TestClient):
    resp = client.get(
        "/admin/security/protection",
        headers={"X-Email": "alice@example.com", "X-Groups": "team-ops"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303, 401, 403)


def test_protection_page_ok_as_admin(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.get("/admin/security/protection", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Protection web" in resp.text
    assert "Ce qui vous protège" in resp.text
    assert "Efficacité" in resp.text
    assert 'action="/admin/security/waf/apply"' not in resp.text
    assert 'id="waf-profile-form"' not in resp.text


def test_protection_degraded_snapshot_and_aggregator_messages(
    client: TestClient, db_session: Session
):
    _seed_profile(db_session)
    resp = client.get("/admin/security/protection", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "non vérifiable" in resp.text.lower()
    assert "snapshot" in resp.text.lower()
    assert "Données indisponibles" in resp.text
    assert "agrégateur" in resp.text.lower()
    assert "0 en-tête(s) actif(s)" not in resp.text


def test_protection_efficiency_measured_zero_distinct_from_unavailable(
    client: TestClient, db_session: Session, tmp_path: Path
):
    _seed_profile(db_session)
    logs = tmp_path / "nginx-logs"
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
    with (
        _patch_snapshot(tmp_path, mode=MODE_OFF),
        patch(
            "app.bastion.modsec_audit_aggregator.resolve_audit_summary_path",
            return_value=logs / "waf-audit-summary.json",
        ),
    ):
        resp = client.get("/admin/security/protection", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "waf-efficiency-measured-zero" in resp.text
    assert "Mesure effectuée" in resp.text
    assert "waf-efficiency-unavailable" not in resp.text


def test_protection_headers_not_contradictory_when_unverifiable(db_session):
    profile = WafProfile(name="P", mode=MODE_ON, anomaly_threshold=5, ip_deny_min_occurrences=3)
    active = {"verifiable": False}
    layers = build_protection_layers(db_session, profile, active, {"present": False})
    headers = next(layer for layer in layers if layer["name"] == "En-têtes de sécurité")
    assert headers["state"] == "non vérifiable"
    assert "0 en-tête" not in headers["detail"]


def test_efficiency_unavailable_has_resolution(tmp_path: Path):
    settings = Settings(
        environment="test",
        database_url="sqlite://",
        nginx_app_logs_dir=str(tmp_path),
    )
    panel = build_efficiency_panel(settings, {"verifiable": True, "aggregate_mode": MODE_OFF})
    assert panel["present"] is False
    assert panel["status"] == "unavailable"
    assert panel.get("resolution")


def test_efficiency_measured_zero_status(tmp_path: Path):
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
        settings, {"verifiable": True, "aggregate_mode": MODE_ON}
    )
    assert panel["present"] is True
    assert panel["status"] == "measured_zero"
    assert panel["inspected"] == 0
