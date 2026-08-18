"""Unit tests for nginx WAF reality reader (Phase B lot 2)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.bastion.nginx_waf_export import MODE_OFF, MODE_ON
from app.bastion.nginx_waf_reality import (
    build_waf_reality_warnings,
    build_waf_ui_context,
    diff_db_vs_export,
    last_sec_rule_engine,
    read_nginx_waf_reality,
    read_security_headers_panel,
)
from app.models import WafExclusion, WafProfile


def _write_minimal_nginx_tree(root: Path, *, engine_mode: str = "Off") -> None:
    mod = root / "modsecurity"
    inc = root / "includes"
    tpl = root / "templates"
    mod.mkdir(parents=True)
    inc.mkdir(parents=True)
    tpl.mkdir(parents=True)

    for fam in ("portal", "subdomain", "public"):
        (mod / f"engine-{fam}.conf").write_text(
            f"SecRuleEngine {engine_mode}\n", encoding="utf-8"
        )
        main = f"""Include /etc/nginx/modsecurity/engine-{fam}.conf
Include /etc/nginx/modsecurity/modsecurity.conf
Include /etc/nginx/modsecurity/crs-setup.conf
Include /etc/nginx/includes/waf-basic.conf
Include /etc/nginx/modsecurity/generated/bastion-exclusions-generated.conf
"""
        (mod / f"main-{fam}.conf").write_text(main, encoding="utf-8")

    (mod / "modsecurity.conf").write_text("# core\n", encoding="utf-8")
    (mod / "crs-setup.conf").write_text(
        'SecAction "id:900110,setvar:tx.inbound_anomaly_score_threshold=5"\n',
        encoding="utf-8",
    )
    (inc / "waf-basic.conf").write_text("# empty\n", encoding="utf-8")
    (inc / "security-headers.conf").write_text(
        'add_header Strict-Transport-Security "max-age=31536000" always;\n'
        'add_header X-Frame-Options "SAMEORIGIN" always;\n',
        encoding="utf-8",
    )
    (tpl / "vhost_sso_portal.conf.template").write_text(
        "# Do not re-add security-headers on :8080\n", encoding="utf-8"
    )
    (root / "sync-acme-tls.sh").write_text(
        'include includes/security-headers.conf\n', encoding="utf-8"
    )


def test_last_sec_rule_engine_last_wins():
    text = "SecRuleEngine On\n# comment\nSecRuleEngine Off\n"
    assert last_sec_rule_engine(text) == MODE_OFF


def test_read_reality_off_when_engine_off(tmp_path: Path):
    _write_minimal_nginx_tree(tmp_path, engine_mode="Off")
    reality = read_nginx_waf_reality(nginx_root=tmp_path)
    assert reality["present"] is True
    assert reality["aggregate_mode"] == MODE_OFF
    assert reality["aggregate_threshold"] == 5
    assert reality["engine_mode_generated_loaded"] is False
    assert reality["crs_setup_generated_loaded"] is False
    assert reality["source_kind"] == "repo_build_context"
    assert reality["verified_in_container"] is False


def test_read_reality_on_no_warning_when_db_matches(tmp_path: Path):
    _write_minimal_nginx_tree(tmp_path, engine_mode="On")
    reality = read_nginx_waf_reality(nginx_root=tmp_path)
    assert reality["aggregate_mode"] == MODE_ON

    profile = WafProfile(name="Production", mode=MODE_ON, anomaly_threshold=5)
    assert build_waf_reality_warnings(profile, reality) == []


def test_warning_when_db_on_but_nginx_off(tmp_path: Path):
    _write_minimal_nginx_tree(tmp_path, engine_mode="Off")
    reality = read_nginx_waf_reality(nginx_root=tmp_path)
    profile = WafProfile(name="Production", mode=MODE_ON, anomaly_threshold=5)
    warnings = build_waf_reality_warnings(profile, reality)
    assert len(warnings) >= 1
    assert "N'EST PAS appliqué" in warnings[0]


def test_diff_db_vs_export_applied_when_equal(tmp_path: Path, db_session: Session):
    profile = WafProfile(
        name="Production",
        mode=MODE_ON,
        anomaly_threshold=5,
        ip_deny_min_occurrences=3,
        portal_login_rate=3,
        portal_api_rate=30,
        portal_login_burst=5,
        portal_api_burst=60,
        is_active=True,
    )
    db_session.add(profile)
    db_session.commit()

    effective = {
        "present": True,
        "mode": MODE_ON,
        "anomaly_threshold": 5,
        "ip_deny_min_occurrences": 3,
        "portal_login_rate": 3,
        "portal_api_rate": 30,
        "portal_login_burst": 5,
        "portal_api_burst": 60,
        "exclusion_count": 0,
        "exclusion_rule_ids": [],
    }
    assert diff_db_vs_export(profile, [], effective) == []


def test_diff_db_vs_export_legacy_json_without_exclusion_rule_ids(db_session: Session):
    """Prod JSON predates lot 2 — missing field must not force En attente."""
    profile = WafProfile(
        name="Production",
        mode=MODE_ON,
        anomaly_threshold=5,
        ip_deny_min_occurrences=3,
        portal_login_rate=3,
        portal_api_rate=30,
        portal_login_burst=5,
        portal_api_burst=60,
        is_active=True,
    )
    db_session.add(profile)
    db_session.add(
        WafExclusion(
            crs_rule_id=942100,
            reason="FP",
            uri_pattern="/admin",
            active=True,
        )
    )
    db_session.commit()
    exclusions = db_session.query(WafExclusion).all()

    effective = {
        "present": True,
        "mode": MODE_ON,
        "anomaly_threshold": 5,
        "ip_deny_min_occurrences": 3,
        "portal_login_rate": 3,
        "portal_api_rate": 30,
        "portal_login_burst": 5,
        "portal_api_burst": 60,
        "exclusion_count": 1,
        # exclusion_rule_ids intentionally absent
    }
    assert diff_db_vs_export(profile, exclusions, effective) == []


def test_diff_db_vs_export_pending_on_mode_change(db_session: Session):
    profile = WafProfile(
        name="Production",
        mode=MODE_ON,
        anomaly_threshold=5,
        ip_deny_min_occurrences=3,
        is_active=True,
    )
    db_session.add(profile)
    db_session.commit()

    effective = {
        "present": True,
        "mode": MODE_OFF,
        "anomaly_threshold": 5,
        "ip_deny_min_occurrences": 3,
        "portal_login_rate": 3,
        "portal_api_rate": 30,
        "portal_login_burst": 5,
        "portal_api_burst": 60,
        "exclusion_count": 0,
        "exclusion_rule_ids": [],
    }
    diffs = diff_db_vs_export(profile, [], effective)
    assert any(d["field"] == "mode" for d in diffs)
    assert diffs[0]["export"] == MODE_OFF
    assert diffs[0]["db"] == MODE_ON


def test_security_headers_panel_follows_fixture(tmp_path: Path):
    _write_minimal_nginx_tree(tmp_path)
    panel = read_security_headers_panel(nginx_root=tmp_path)
    assert panel["present"] is True
    names = [h["name"] for h in panel["headers"]]
    assert "Strict-Transport-Security" in names
    assert "X-Frame-Options" in names
    assert panel["included_on_443"] is True

    hdr = tmp_path / "includes" / "security-headers.conf"
    hdr.write_text(
        'add_header X-Content-Type-Options "nosniff" always;\n', encoding="utf-8"
    )
    panel2 = read_security_headers_panel(nginx_root=tmp_path)
    assert panel2["headers"][0]["name"] == "X-Content-Type-Options"


def test_build_ui_context_export_pending(tmp_path: Path, db_session: Session):
    from app.sso_settings import Settings

    settings = Settings(environment="test", database_url="sqlite://")
    _write_minimal_nginx_tree(tmp_path, engine_mode="Off")
    profile = WafProfile(
        name="Production",
        mode=MODE_ON,
        anomaly_threshold=5,
        ip_deny_min_occurrences=3,
        portal_login_rate=3,
        portal_api_rate=30,
        is_active=True,
    )
    db_session.add(profile)
    db_session.commit()

    mod_dir = Path("./exports/modsecurity")
    mod_dir.mkdir(parents=True, exist_ok=True)
    status_path = mod_dir / "waf-effective-status.json"
    status_path.write_text(
        json.dumps(
            {
                "mode": MODE_OFF,
                "anomaly_threshold": 5,
                "profile_name": "Production",
                "ip_deny_count": 0,
                "ip_deny_min_occurrences": 3,
                "exclusion_count": 0,
                "exclusion_rule_ids": [],
                "portal_login_rate": 3,
                "portal_api_rate": 30,
                "portal_login_burst": 5,
                "portal_api_burst": 60,
            }
        ),
        encoding="utf-8",
    )

    ctx = build_waf_ui_context(
        db_session, settings, profile, [], nginx_root=tmp_path
    )
    assert ctx["export_pending"] is True
    assert ctx["reality_warnings"]
    assert ctx["control_effect"]["mode"] is False
    assert ctx["control_effect"]["anomaly_threshold"] is False
