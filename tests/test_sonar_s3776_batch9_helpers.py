"""Unit coverage for S3776 helpers extracted in batch9."""

from __future__ import annotations

from collections import Counter
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.bastion.ip_geolocation import _unique_public_ips
from app.bastion.modsec_audit_aggregator import _accumulate_hourly_bucket
from app.db.hot_store import _wizard_step_status, build_hot_store_wizard_steps
from app.oidc_bff import _oidc_claims_from_payload, _parse_oidc_groups
from app.admin.rbac_access import _redirect_url_after_grant_delete


def test_wizard_step_status_and_steps():
    assert _wizard_step_status(locked=True) == "locked"
    assert _wizard_step_status(locked=False, done=True) == "done"
    assert _wizard_step_status(locked=False, failed=True) == "failed"
    assert _wizard_step_status(locked=False, skipped=True) == "skipped"
    assert _wizard_step_status(locked=False) == "todo"

    steps = build_hot_store_wizard_steps(
        configured=True,
        last_test_ok=True,
        schema_prepared=True,
        migrate_done=False,
        migrate_skipped=True,
        enabled=False,
    )
    by_id = {s["id"]: s for s in steps}
    assert by_id["config"]["status"] == "done"
    assert by_id["test"]["status"] == "done"
    assert by_id["migrate"]["status"] == "skipped"
    assert by_id["enable"]["status"] == "todo"
    assert by_id["enable"]["locked"] is False


def test_accumulate_hourly_bucket():
    rules: Counter[str] = Counter()
    hosts: Counter[str] = Counter()
    attackers: Counter[str] = Counter()
    fams: Counter[str] = Counter()
    i, d, b, c = _accumulate_hourly_bucket(
        {
            "inspected": 10,
            "detections": 3,
            "blocks": 1,
            "critical": 0,
            "rules": {"941100": 2},
            "hosts": {"app.example.com": 3},
            "attackers": {"10.0.0.1": 1},
            "families": {"sqli": 2},
        },
        rules=rules,
        hosts=hosts,
        attackers=attackers,
        fam_counter=fams,
    )
    assert (i, d, b, c) == (10, 3, 1, 0)
    assert rules["941100"] == 2
    assert hosts["app.example.com"] == 3
    assert attackers["10.0.0.1"] == 1
    assert fams["sqli"] == 2


def test_parse_oidc_groups_and_claims():
    assert _parse_oidc_groups(["a", " b ", 3, ""]) == ("a", "b", "3")
    assert _parse_oidc_groups("x,y,") == ("x", "y")
    assert _parse_oidc_groups(None) == ()

    claims = _oidc_claims_from_payload(
        {
            "jti": "j1",
            "sub": "s1",
            "realm": "default",
            "username": "alice",
            "exp": 123,
            "groups": ["ops"],
            "email": "alice@example.com",
        }
    )
    assert claims is not None
    assert claims.jti == "j1"
    assert claims.groups == ("ops",)
    assert claims.email == "alice@example.com"
    assert _oidc_claims_from_payload({"jti": "j", "sub": "s"}) is None


def test_unique_public_ips():
    out = _unique_public_ips(["8.8.8.8", "8.8.8.8", "10.0.0.1", "", "1.1.1.1"])
    assert out == ["8.8.8.8", "1.1.1.1"]


def test_redirect_url_after_grant_delete():
    app_grant = SimpleNamespace(
        resource_type="application",
        application_id=9,
        file_id=None,
        subject_type="user",
        rbac_group_id=None,
        keycloak_user_id="u1",
    )
    assert _redirect_url_after_grant_delete(app_grant, "/admin/rbac") == (
        "/admin/rbac/applications/9"
    )
    custom = _redirect_url_after_grant_delete(app_grant, "/admin/rbac/users")
    assert custom == "/admin/rbac/users"
