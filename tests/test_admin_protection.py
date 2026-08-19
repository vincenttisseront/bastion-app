"""Integration tests for unified WAF page (lot 6)."""

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
        "families": {
            "portal": {**fam, "family": "portal"},
            "subdomain": {**fam, "family": "subdomain"},
            "public": {**fam, "family": "public"},
        },
        "aggregate_mode": mode,
        "aggregate_threshold": 5,
        "security_headers": {
            "headers": [{"name": "Strict-Transport-Security", "value": "max-age=31536000"}],
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


def test_protection_redirects_to_waf_bilan(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.get("/admin/security/protection", headers=ADMIN_HEADERS, follow_redirects=False)
    assert resp.status_code == 301
    assert resp.headers["location"] == "/admin/security/waf#bilan"


def test_waf_opens_bilan_tab_by_default(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert 'data-tab="bilan"' in resp.text
    assert 'id="bilan"' in resp.text
    assert "Ce qui vous protège" in resp.text
    assert 'id="profile"' in resp.text
    assert "waf-bilan-grid" in resp.text


def test_apply_disabled_on_bilan_tab(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert "setConfigActions" in resp.text
    assert "currentTab() === 'bilan'" in resp.text
    assert 'data-export-pending=' in resp.text


def test_technical_tab_not_collapsed(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert 'data-tab="technical"' in resp.text
    assert 'id="technical"' in resp.text
    assert 'waf-technical-details' not in resp.text
    assert resp.text.count("<details") == resp.text.count("</details>")


def test_degraded_unavailable_vs_measured_zero(client: TestClient, db_session: Session, tmp_path: Path):
    _seed_profile(db_session)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert "waf-efficiency-unavailable" in resp.text
    assert "agrégateur" in resp.text.lower()

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
                "rule_families": [],
            }
        },
        "series": {"24h": [], "7d": []},
    }
    (logs / "waf-audit-summary.json").write_text(json.dumps(summary), encoding="utf-8")
    with (
        _patch_snapshot(tmp_path, mode=MODE_OFF),
        patch(
            "app.bastion.modsec_audit_aggregator.resolve_audit_summary_path",
            return_value=logs / "waf-audit-summary.json",
        ),
    ):
        resp2 = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert "waf-efficiency-measured-zero" in resp2.text or "Mesure effectuée" in resp2.text
    assert "waf-chart-unavailable" in resp2.text or "waf-chart-measured_zero" in resp2.text


def test_no_external_network_on_page(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    lower = resp.text.lower()
    assert "cdn.jsdelivr" not in lower
    assert "unpkg.com" not in lower
    assert "chart.js" not in lower
    assert "waf-chart" in resp.text


def test_responsive_bilan_grid_css_present(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert "waf-bilan-grid" in resp.text


def test_headers_layer_compact_not_contradictory(db_session):
    profile = WafProfile(name="P", mode=MODE_ON, anomaly_threshold=5, ip_deny_min_occurrences=3)
    layers = build_protection_layers(db_session, profile, {"verifiable": False}, {"present": False})
    headers = next(layer for layer in layers if layer["name"] == "En-têtes de sécurité")
    assert headers["state"] == "non vérifiable"
    assert "detail_short" in headers
    assert "0 en-tête" not in headers["detail_short"]


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
    assert panel["status"] == "measured_zero"
