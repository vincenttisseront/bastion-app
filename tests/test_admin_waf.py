"""Integration tests for /admin/security/waf."""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

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


def test_waf_page_requires_admin(client: TestClient):
    resp = client.get("/admin/security/waf", headers=USER_HEADERS, follow_redirects=False)
    assert resp.status_code in (302, 303, 401, 403)


def test_waf_page_ok_as_admin(client: TestClient, db_session: Session):
    _seed_profile(db_session)
    resp = client.get("/admin/security/waf", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "ModSecurity" in resp.text or "WAF" in resp.text
    assert 'id="waf-tabs"' in resp.text
    assert 'class="form-input"' in resp.text
    assert 'class="form-select"' in resp.text
    assert "bastionConfirm" in resp.text
    assert 'id="bastion-modal"' in resp.text or "bastion-modal" in resp.text


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
