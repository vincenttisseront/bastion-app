"""Unit tests for nginx WAF reality reader (Phase B lot 2.1 — container snapshot)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.bastion.nginx_waf_export import MODE_DETECTION, MODE_OFF, MODE_ON
from app.bastion.nginx_waf_reality import (
    build_waf_reality_warnings,
    build_waf_ui_context,
    diff_db_vs_export,
    last_sec_rule_engine,
    read_nginx_waf_reality_from_repo,
    read_nginx_waf_snapshot,
    read_security_headers_from_repo,
    resolve_nginx_conf_root,
    resolve_nginx_waf_snapshot_path,
)
from app.models import WafProfile


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
        'add_header Strict-Transport-Security "max-age=31536000" always;\n',
        encoding="utf-8",
    )
    (tpl / "vhost_sso_portal.conf.template").write_text(
        "# Do not re-add security-headers on :8080\n", encoding="utf-8"
    )
    (root / "sync-acme-tls.sh").write_text(
        'include includes/security-headers.conf\n', encoding="utf-8"
    )


def _family_block(mode: str = "off") -> dict:
    return {
        "family": "portal",
        "sec_rule_engine": mode,
        "sec_rule_engine_static": mode,
        "anomaly_threshold": 5,
        "anomaly_source": "crs-setup.conf (statique)",
        "engine_mode_generated_loaded": False,
        "crs_setup_generated_loaded": False,
        "engine_file": "/etc/nginx/modsecurity/engine-portal.conf",
    }


def _write_snapshot(
    path: Path,
    *,
    mode: str = MODE_OFF,
    minutes_ago: int = 0,
) -> None:
    generated_at = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    fam = _family_block(mode)
    payload = {
        "schema_version": 1,
        "generated_at": generated_at.isoformat(),
        "nginx_version": "nginx/1.30.4",
        "image_tag": "bastion-nginx:test",
        "nginx_t_ok": True,
        "nginx_t_excerpt": "SecRuleEngine Off",
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


def test_last_sec_rule_engine_last_wins():
    text = "SecRuleEngine On\n# comment\nSecRuleEngine Off\n"
    assert last_sec_rule_engine(text) == MODE_OFF


def test_portal_engine_mode_ignores_mixed_aggregate():
    from app.bastion.nginx_waf_reality import portal_engine_mode

    active = {
        "verifiable": True,
        "aggregate_mode": "mixed",
        "families": {
            "portal": {"sec_rule_engine": MODE_DETECTION},
            "subdomain": {"sec_rule_engine": MODE_OFF},
        },
    }
    assert portal_engine_mode(active) == MODE_DETECTION


def test_read_snapshot_present(tmp_path: Path):
    snap = tmp_path / "nginx-waf-snapshot.json"
    _write_snapshot(snap, mode=MODE_OFF)
    reality = read_nginx_waf_snapshot(snapshot_path=snap)
    assert reality["present"] is True
    assert reality["verifiable"] is True
    assert reality["aggregate_mode"] == MODE_OFF
    assert reality["source_kind"] == "nginx_container_snapshot"


def test_read_snapshot_absent_non_verifiable(tmp_path: Path):
    missing = tmp_path / "missing.json"
    reality = read_nginx_waf_snapshot(snapshot_path=missing)
    assert reality["present"] is False
    assert reality["verifiable"] is False


def test_read_snapshot_stale(tmp_path: Path):
    snap = tmp_path / "nginx-waf-snapshot.json"
    _write_snapshot(snap, mode=MODE_OFF, minutes_ago=30)
    reality = read_nginx_waf_snapshot(snapshot_path=snap)
    assert reality["stale"] is True


def test_read_reality_from_repo_dev_only(tmp_path: Path):
    _write_minimal_nginx_tree(tmp_path, engine_mode="Off")
    reality = read_nginx_waf_reality_from_repo(nginx_root=tmp_path)
    assert reality["source_kind"] == "repo_intent"
    assert reality["verifiable"] is False


def test_no_cwd_path_resolution_in_module():
    source = Path(__file__).parents[1] / "app" / "bastion" / "nginx_waf_reality.py"
    text = source.read_text(encoding="utf-8")
    assert "Path.cwd()" not in text
    assert "resolve_nginx_docker_root" not in text


def test_warning_when_db_on_but_nginx_off(tmp_path: Path):
    snap = tmp_path / "nginx-waf-snapshot.json"
    _write_snapshot(snap, mode=MODE_OFF)
    reality = read_nginx_waf_snapshot(snapshot_path=snap)
    profile = WafProfile(name="Production", mode=MODE_ON, anomaly_threshold=5)
    warnings = build_waf_reality_warnings(profile, reality)
    assert warnings == []


def test_warning_when_snapshot_missing():
    profile = WafProfile(name="Production", mode=MODE_ON, anomaly_threshold=5)
    reality = {"present": False, "verifiable": False, "error": "snapshot nginx absent"}
    warnings = build_waf_reality_warnings(profile, reality)
    assert warnings == []


def test_build_ui_context_with_snapshot(tmp_path: Path, db_session: Session):
    from app.sso_settings import Settings

    settings = Settings(environment="test", database_url="sqlite://")
    snap = tmp_path / "nginx-waf-snapshot.json"
    _write_snapshot(snap, mode=MODE_OFF)
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
    (mod_dir / "waf-effective-status.json").write_text(
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
        db_session, settings, profile, [], snapshot_path=snap
    )
    assert ctx["active"]["verifiable"] is True
    assert ctx["security_headers_panel"]["verifiable"] is True


def test_resolve_paths_use_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("BASTION_NGINX_WAF_SNAPSHOT_PATH", str(tmp_path / "snap.json"))
    assert resolve_nginx_waf_snapshot_path() == tmp_path / "snap.json"
    _write_minimal_nginx_tree(tmp_path / "nginx")
    monkeypatch.setenv("BASTION_NGINX_CONF_ROOT", str(tmp_path / "nginx"))
    assert resolve_nginx_conf_root() == tmp_path / "nginx"
