"""Integration tests for /admin/security/waf."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.bastion.nginx_waf_export import MODE_OFF, MODE_ON
from app.models import WafExclusion, WafProfile

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}
USER_HEADERS = {
    "X-Email": "alice@example.com",
    "X-Groups": "team-ops",
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


def _write_export_status(*, mode: str = MODE_ON, include_exclusion_ids: bool = True) -> None:
    payload = {
        "mode": mode,
        "anomaly_threshold": 5,
        "profile_name": "Production",
        "ip_deny_count": 0,
        "ip_deny_min_occurrences": 3,
        "exclusion_count": 0,
        "portal_login_rate": 3,
        "portal_api_rate": 30,
        "portal_login_burst": 5,
        "portal_api_burst": 60,
    }
    if include_exclusion_ids:
        payload["exclusion_rule_ids"] = []
    mod_dir = Path("./exports/modsecurity")
    mod_dir.mkdir(parents=True, exist_ok=True)
    (mod_dir / "waf-effective-status.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )


def test_waf_page_requires_admin(client: TestClient):
    resp = client.get("/admin/security/waf", headers=USER_HEADERS, follow_redirects=False)
    assert resp.status_code in (302, 303, 401, 403)


def test_waf_page_ok_as_admin(client: TestClient, db_session: Session, tmp_path: Path):
    _seed_profile(db_session)
    with _patch_snapshot(tmp_path, mode=MODE_OFF):
        resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Couches de protection" in resp.text
    assert 'data-tab="bilan"' in resp.text
    assert 'class="form-input"' in resp.text
    assert "bastionConfirm" in resp.text


def test_waf_page_shows_reality_banner_when_engine_off(
    client: TestClient, db_session: Session, tmp_path: Path
):
    _seed_profile(db_session)
    _write_export_status(mode=MODE_ON)
    with _patch_snapshot(tmp_path, mode=MODE_OFF):
        resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
        assert resp.status_code == 200
        assert "INACTIVE" in resp.text
        assert 'data-tab="reactivation"' in resp.text or 'id="tab-reactivation"' in resp.text
        assert "Mode non pilotable" in resp.text or "ne peut pas réactiver" in resp.text or "DetectionOnly" in resp.text
        assert "non appliqué en nginx" in resp.text


def test_waf_page_no_banner_when_engine_on_snapshot(
    client: TestClient, db_session: Session, tmp_path: Path
):
    _seed_profile(db_session)
    _write_export_status(mode=MODE_ON)
    with _patch_snapshot(tmp_path, mode=MODE_ON):
        resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Inspection ACTIVE" in resp.text


def test_waf_page_applied_badge_when_db_matches_export(
    client: TestClient, db_session: Session
):
    _seed_profile(db_session)
    _write_export_status(mode=MODE_ON)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert ">Appliqué<" in resp.text
    assert 'disabled aria-disabled="true"' in resp.text


def test_waf_page_applied_badge_with_legacy_export_json(
    client: TestClient, db_session: Session
):
    _seed_profile(db_session)
    _write_export_status(mode=MODE_ON, include_exclusion_ids=False)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert ">Appliqué<" in resp.text
    assert 'badge badge-warn">En attente' not in resp.text


def test_waf_page_pending_badge_after_profile_change(
    client: TestClient, db_session: Session
):
    _seed_profile(db_session)
    _write_export_status(mode=MODE_OFF)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert ">En attente<" in resp.text
    assert "waf-pending-list" in resp.text


def test_waf_page_security_headers_tab(
    client: TestClient, db_session: Session, tmp_path: Path
):
    _seed_profile(db_session)
    with _patch_snapshot(tmp_path, mode=MODE_OFF):
        resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert 'data-tab="headers"' in resp.text
    assert "Strict-Transport-Security" in resp.text


def test_waf_page_non_verifiable_without_snapshot(
    client: TestClient, db_session: Session
):
    _seed_profile(db_session)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "non vérifiable" in resp.text.lower() or "Non vérifiable" in resp.text
    assert "snapshot" in resp.text.lower()


def test_waf_page_last_apply_unknown_when_legacy_export(
    client: TestClient, db_session: Session
):
    _seed_profile(db_session)
    _write_export_status(mode=MODE_ON, include_exclusion_ids=False)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "waf-last-apply" in resp.text
    assert "inconnu" in resp.text.lower() or "antérieur" in resp.text.lower()


def test_waf_page_last_apply_shown_when_stamped(
    client: TestClient, db_session: Session
):
    from app.bastion.nginx_waf_export import record_waf_apply_metadata
    from app.sso_settings import Settings

    _seed_profile(db_session)
    _write_export_status(mode=MODE_ON)
    record_waf_apply_metadata(
        Settings(environment="test", database_url="sqlite://"),
        actor="admin@example.com",
        nginx_t_ok=True,
        nginx_t_detail="nginx -t ok",
    )
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Dernier Appliquer" in resp.text
    assert "admin@example.com" in resp.text
    assert "nginx -t OK" in resp.text


def test_waf_page_does_not_aggregate_audit_log_on_render(
    client: TestClient, db_session: Session, tmp_path: Path
):
    """Page must read pre-computed summary only, never parse modsec_audit.log."""
    _seed_profile(db_session)
    logs = tmp_path / "nginx-logs"
    logs.mkdir()
    audit_log = logs / "modsec_audit.log"
    audit_log.write_text("X" * 10_000_000, encoding="utf-8")
    summary = {
        "schema_version": 1,
        "generated_at": "2026-08-19T12:00:00+00:00",
        "log_available": True,
        "windows": {
            "24h": {
                "inspected": 42,
                "detections": 3,
                "blocks": 1,
                "block_rate_pct": 2.4,
                "top_rules": [],
                "top_hosts": [],
            }
        },
    }
    (logs / "waf-audit-summary.json").write_text(json.dumps(summary), encoding="utf-8")

    def _forbid_log_read(path, *args, **kwargs):
        if "modsec_audit.log" in str(path):
            raise AssertionError("modsec_audit.log must not be read during page render")
        from pathlib import Path as _Path

        return _Path(path).open(*args, **kwargs)

    with (
        patch(
            "app.bastion.modsec_audit_aggregator.resolve_modsec_audit_log_path",
            return_value=audit_log,
        ),
        patch(
            "app.bastion.modsec_audit_aggregator.resolve_audit_summary_path",
            return_value=logs / "waf-audit-summary.json",
        ),
        patch("app.bastion.modsec_audit_aggregator.run_aggregation") as mock_agg,
        patch("builtins.open", side_effect=_forbid_log_read),
    ):
        resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)

    assert resp.status_code == 200
    mock_agg.assert_not_called()
    assert "42" in resp.text


def test_waf_status_redirects_to_bilan(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.get("/admin/security/waf/status", headers=ADMIN_HEADERS, follow_redirects=False)
    assert resp.status_code == 301
    assert resp.headers["location"] == "/admin/security/waf#bilan"


def test_waf_page_anti_bruteforce_alert_when_policy_disabled(
    client: TestClient, db_session: Session
):
    from app.security.banning.service import get_or_create_policy

    _seed_profile(db_session)
    policy = get_or_create_policy(db_session)
    policy.enabled = False
    db_session.commit()

    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "désactivé (global)" in resp.text
    assert 'class="badge badge-err"' in resp.text or "badge-err" in resp.text


def test_waf_diagnostic_json_download(client: TestClient, db_session: Session, tmp_path: Path):
    _seed_profile(db_session)
    _write_export_status(mode=MODE_ON)
    with _patch_snapshot(tmp_path, mode=MODE_OFF):
        resp = client.get("/admin/security/waf/diagnostic.json", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "application/json" in resp.headers.get("content-type", "")
    assert "attachment" in resp.headers.get("content-disposition", "")
    data = resp.json()
    assert data["kind"] == "bastion-waf-diagnostic"
    assert data["expected"]["profile"]["mode"] == "on"
    assert data["actual"]["verifiable"] is True
    assert data["actual"]["aggregate_mode"] == MODE_OFF
    assert "schema_version" in data


def test_waf_page_embeds_diagnostic_export(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert 'id="waf-diagnostic-json"' in resp.text
    assert "bastion-waf-diagnostic" in resp.text
    assert 'href="/admin/security/waf/diagnostic.json"' in resp.text


def test_waf_threshold_rejected_out_of_bounds(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.post(
        "/admin/security/waf/profile",
        headers=ADMIN_HEADERS,
        data={
            "mode": "on",
            "anomaly_threshold": "99",
            "profile_preset": "Custom",
            "ip_deny_min_occurrences": "3",
            "portal_login_rate": "3",
            "portal_api_rate": "30",
            "portal_login_burst": "5",
            "portal_api_burst": "60",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    profile = db_session.query(WafProfile).filter_by(is_active=True).one()
    assert profile.anomaly_threshold == 5


def test_waf_exclusion_requires_reason(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.post(
        "/admin/security/waf/exclusions/add",
        headers=ADMIN_HEADERS,
        data={
            "reason": "   ",
            "crs_rule_id": "942100",
            "uri_pattern": "/admin",
            "host": "",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert db_session.query(WafExclusion).count() == 0


def test_waf_exclusion_add_ok(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.post(
        "/admin/security/waf/exclusions/add",
        headers=ADMIN_HEADERS,
        data={
            "reason": "FP confirmé",
            "crs_rule_id": "942100",
            "uri_pattern": "/admin/apps/analyze-login-form",
            "host": "",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    row = db_session.query(WafExclusion).one()
    assert row.active is True
    assert row.crs_rule_id == 942100


def test_waf_apply_nginx_t_failure(client: TestClient, db_session: Session):
    _seed_profile(db_session)

    def boom(*_a, **_k):
        return {
            "ok": False,
            "error": "nginx: [emerg] simulated",
            "paths": {},
            "restored": [],
            "effective": {"present": False},
        }

    with patch("app.admin.waf.waf_service.apply_waf", side_effect=boom):
        resp = client.post(
            "/admin/security/waf/apply",
            headers=ADMIN_HEADERS,
            follow_redirects=False,
        )
    assert resp.status_code == 302


def test_waf_ban_ip_from_bilan(client: TestClient, db_session: Session):
    from app.models import SecurityBan

    _seed_profile(db_session)
    resp = client.post(
        "/admin/security/waf/actions/ban-ip",
        headers=ADMIN_HEADERS,
        data={
            "ip": "198.51.100.50",
            "ban_mode": "temporary",
            "ban_minutes": "1440",
            "reason": "WAF test ban",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "#bilan" in (resp.headers.get("location") or "")
    ban = (
        db_session.query(SecurityBan)
        .filter_by(target_type="ip", target="198.51.100.50")
        .one()
    )
    assert ban.lifted_at is None
    assert ban.permanent is False


def test_waf_ban_ip_permanent_requires_confirm(client: TestClient, db_session: Session):
    from app.models import SecurityBan

    _seed_profile(db_session)
    resp = client.post(
        "/admin/security/waf/actions/ban-ip",
        headers=ADMIN_HEADERS,
        data={
            "ip": "198.51.100.51",
            "ban_mode": "permanent",
            "reason": "WAF permanent",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert (
        db_session.query(SecurityBan)
        .filter_by(target="198.51.100.51")
        .count()
        == 0
    )

    resp2 = client.post(
        "/admin/security/waf/actions/ban-ip",
        headers=ADMIN_HEADERS,
        data={
            "ip": "198.51.100.51",
            "ban_mode": "permanent",
            "confirm_permanent": "on",
            "reason": "WAF permanent",
        },
        follow_redirects=False,
    )
    assert resp2.status_code == 302
    ban = db_session.query(SecurityBan).filter_by(target="198.51.100.51").one()
    assert ban.permanent is True


def test_waf_exclude_rule_from_event(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.post(
        "/admin/security/waf/actions/exclude-rule",
        headers=ADMIN_HEADERS,
        data={
            "crs_rule_id": "942100",
            "host": "portal.example.com",
            "uri_pattern": "/api/test",
            "reason": "FP depuis bilan",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    row = db_session.query(WafExclusion).one()
    assert row.crs_rule_id == 942100
    assert row.host == "portal.example.com"
    assert row.active is True
