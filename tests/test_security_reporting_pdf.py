"""Compliance PDF reporting — aggregator, PDF engine, admin export route."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import AdminMfaCredential
from app.reporting.pdf_engine import render_security_compliance_pdf
from app.reporting.security_report import (
    build_security_report,
    generate_and_store_report,
    period_window,
)
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}
USER_HEADERS = {
    "X-Email": "alice@example.com",
    "X-Groups": "team-ops",
}


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        portal_domain="portal.example.com",
        portal_data_dir=str(tmp_path / "data"),
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )


def test_period_window_weekly_and_monthly():
    now = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
    weekly = period_window("weekly", now=now)
    assert weekly["name"] == "weekly"
    assert "2026-10-08" in weekly["start"]
    monthly = period_window("monthly", now=now)
    assert monthly["name"] == "monthly"
    assert monthly["start"].startswith("2026-10-01")


def test_build_security_report_and_pdf_bytes(db_session: Session, tmp_path: Path):
    settings = _settings(tmp_path)
    db_session.add(
        AdminMfaCredential(
            user_email="admin@example.com",
            totp_enabled=True,
            totp_secret="x",
            webauthn_enabled=False,
        )
    )
    db_session.commit()

    fake_analytics = {
        "present": True,
        "kpis": {
            "requests_evaluated": 100,
            "blocked_intents": 10,
            "blocks_executed": 8,
        },
        "network": {
            "rate_limit_429_24h": 3,
            "auto_bans_active": 1,
            "allowlist_ips": 2,
            "promoted_deny_count": 1,
        },
        "packs_status": {"armament_ratio": 0.5},
        "top_rules": {
            "combined": [
                {"rule_id": "942100", "label": "SQLi", "count": 4},
            ]
        },
        "portal_mode": "on",
    }
    fake_runtime = {
        "ok": True,
        "runtime_status": "hardened",
        "is_root": False,
        "read_only_fs": True,
        "no_new_privileges": True,
    }
    fake_mtls = {
        "ca": {
            "subject": "CN=Bastion Internal CA",
            "fingerprint_sha256": "abc123",
            "not_before": "2026-01-01T00:00:00+00:00",
            "not_after": "2030-01-01T00:00:00+00:00",
            "serial_hex": "01",
            "path": "/tmp/ca.pem",
        },
        "clients": [],
        "counts": {"total": 0, "active": 0, "revoked": 0},
    }

    with (
        patch(
            "app.bastion.waf_analytics.build_waf_analytics_summary",
            return_value=fake_analytics,
        ),
        patch(
            "app.security.runtime_check.check_runtime_hardening",
            return_value=fake_runtime,
        ),
        patch(
            "app.acme.mtls_client_service.mtls_dashboard_payload",
            return_value=fake_mtls,
        ),
    ):
        payload = build_security_report(db_session, settings, period="monthly")
        pdf = render_security_compliance_pdf(payload)

    assert payload["executive"]["compliance_score"] >= 50
    assert payload["identity"]["mfa_enrolled"] == 1
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 500


def test_generate_and_store_writes_reports_dir(
    db_session: Session, tmp_path: Path
):
    settings = _settings(tmp_path)
    with (
        patch(
            "app.bastion.waf_analytics.build_waf_analytics_summary",
            return_value={
                "present": False,
                "kpis": {},
                "network": {},
                "packs_status": {},
                "top_rules": {},
                "portal_mode": None,
            },
        ),
        patch(
            "app.security.runtime_check.check_runtime_hardening",
            return_value={
                "ok": False,
                "runtime_status": "loose",
                "is_root": True,
                "read_only_fs": False,
                "no_new_privileges": False,
            },
        ),
        patch(
            "app.acme.mtls_client_service.mtls_dashboard_payload",
            return_value={
                "ca": None,
                "clients": [],
                "counts": {"total": 0, "active": 0, "revoked": 0},
            },
        ),
    ):
        _payload, pdf, path = generate_and_store_report(
            db_session,
            settings,
            period="weekly",
            actor="test",
            store=True,
            audit=True,
        )
    assert pdf.startswith(b"%PDF")
    assert path is not None
    assert path.exists()
    assert "reports" in str(path)
    assert path.read_bytes().startswith(b"%PDF")


def test_export_route_admin_200_pdf(client: TestClient, tmp_path, monkeypatch):
    monkeypatch.setenv("PORTAL_DATA_DIR", str(tmp_path / "data"))
    with (
        patch(
            "app.bastion.waf_analytics.build_waf_analytics_summary",
            return_value={
                "present": True,
                "kpis": {
                    "requests_evaluated": 1,
                    "blocked_intents": 0,
                    "blocks_executed": 0,
                },
                "network": {
                    "rate_limit_429_24h": 0,
                    "auto_bans_active": 0,
                    "allowlist_ips": 0,
                    "promoted_deny_count": 0,
                },
                "packs_status": {"armament_ratio": 0.0},
                "top_rules": {},
                "portal_mode": "detection",
            },
        ),
        patch(
            "app.security.runtime_check.check_runtime_hardening",
            return_value={
                "ok": False,
                "runtime_status": "loose",
                "is_root": True,
                "read_only_fs": False,
                "no_new_privileges": None,
            },
        ),
        patch(
            "app.acme.mtls_client_service.mtls_dashboard_payload",
            return_value={
                "ca": None,
                "clients": [],
                "counts": {"total": 0, "active": 0, "revoked": 0},
            },
        ),
    ):
        resp = client.post(
            "/admin/security/reporting/export?period=monthly",
            headers=ADMIN_HEADERS,
        )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/pdf")
    assert resp.content.startswith(b"%PDF")
    assert "attachment" in resp.headers.get("content-disposition", "")


def test_export_route_non_admin_forbidden(client: TestClient):
    resp = client.post(
        "/admin/security/reporting/export?period=weekly",
        headers=USER_HEADERS,
    )
    assert resp.status_code in (302, 403)


def test_no_weasyprint_dependency():
    import importlib.util

    assert importlib.util.find_spec("weasyprint") is None
    assert importlib.util.find_spec("reportlab") is not None


def test_bilan_page_has_export_button(client: TestClient, tmp_path):
    from unittest.mock import patch as _patch

    snap = tmp_path / "nginx-waf-snapshot.json"
    snap.write_text("{}", encoding="utf-8")
    with _patch(
        "app.bastion.nginx_waf_reality.resolve_nginx_waf_snapshot_path",
        return_value=snap,
    ):
        resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Exporter le rapport de conformité (PDF)" in resp.text
    assert "/admin/security/reporting/export" in resp.text
