"""Integration tests for /admin/security/waf."""

from __future__ import annotations

import json
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


def test_waf_page_ok_as_admin(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "ModSecurity" in resp.text or "WAF" in resp.text
    assert 'id="waf-tabs"' in resp.text
    assert "Moteur CRS" in resp.text
    assert "Souhaité (DB)" in resp.text
    assert "non vérifié dans le conteneur" in resp.text
    assert 'class="form-input"' in resp.text
    assert 'class="form-select"' in resp.text
    assert "bastionConfirm" in resp.text
    assert 'id="bastion-modal"' in resp.text or "bastion-modal" in resp.text


def test_waf_page_shows_reality_banner_when_engine_off(
    client: TestClient, db_session: Session
):
    _seed_profile(db_session)
    _write_export_status(mode=MODE_ON)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "waf-reality-banner" in resp.text
    assert "EST PAS appliqué" in resp.text
    assert "non appliqué en nginx" in resp.text


def test_waf_page_no_banner_when_engine_on_fixture(
    client: TestClient, db_session: Session, tmp_path
):
    _seed_profile(db_session)
    _write_export_status(mode=MODE_ON)

    mod = tmp_path / "modsecurity"
    inc = tmp_path / "includes"
    tpl = tmp_path / "templates"
    mod.mkdir(parents=True)
    inc.mkdir(parents=True)
    tpl.mkdir(parents=True)
    for fam in ("portal", "subdomain", "public"):
        (mod / f"engine-{fam}.conf").write_text("SecRuleEngine On\n", encoding="utf-8")
        (mod / f"main-{fam}.conf").write_text(
            f"Include /etc/nginx/modsecurity/engine-{fam}.conf\n"
            f"Include /etc/nginx/modsecurity/crs-setup.conf\n",
            encoding="utf-8",
        )
    (mod / "crs-setup.conf").write_text(
        'SecAction "id:900110,setvar:tx.inbound_anomaly_score_threshold=5"\n',
        encoding="utf-8",
    )
    (inc / "security-headers.conf").write_text("", encoding="utf-8")
    (tpl / "vhost_sso_portal.conf.template").write_text("", encoding="utf-8")
    (tmp_path / "sync-acme-tls.sh").write_text("", encoding="utf-8")

    with patch(
        "app.bastion.nginx_waf_reality.resolve_nginx_docker_root", return_value=tmp_path
    ):
        resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "waf-reality-banner" not in resp.text


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
    assert 'badge badge-ok">Appliqué' in resp.text
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


def test_waf_page_security_headers_tab(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert 'data-tab="headers"' in resp.text
    assert "Strict-Transport-Security" in resp.text
    assert "non défini — hors périmètre" in resp.text


def test_waf_page_anti_bruteforce_is_link(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert "Règles anti-bruteforce (Banning)" in resp.text
    assert 'href="/admin/security#banning"' in resp.text


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
    assert "Dernier Appliquer réussi" in resp.text
    assert "admin@example.com" in resp.text
    assert "nginx -t OK" in resp.text


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
