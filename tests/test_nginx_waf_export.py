"""Unit tests for WAF nginx export (Phase B)."""

from __future__ import annotations

from pathlib import Path

from app.bastion.nginx_waf_export import (
    apply_waf_exports,
    clamp_anomaly_threshold,
    list_promoted_deny_ips,
    read_effective_status,
    record_waf_apply_metadata,
    render_crs_setup_generated,
    render_engine_mode_generated,
    render_exclusions_generated,
    render_ip_deny_conf,
    write_waf_exports,
)
from app.models import SecurityBan, WafExclusion, WafProfile
from app.sso_settings import Settings


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        portal_domain="portal.example.fr",
        sso_portal_default_realm_slug="ar-systems",
        exports_dir=str(tmp_path / "exports"),
        portal_data_dir=str(tmp_path / "data"),
        vault_portal_internal_token="test-secret",
    )  # type: ignore[call-arg]


def test_clamp_anomaly_threshold():
    assert clamp_anomaly_threshold(1) == 3
    assert clamp_anomaly_threshold(5) == 5
    assert clamp_anomaly_threshold(99) == 10
    assert clamp_anomaly_threshold(None) == 5


def test_write_waf_exports_profile_and_exclusion(db_session, tmp_path):
    settings = _settings(tmp_path)
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
    db_session.add(
        WafExclusion(
            uri_pattern="/admin/apps/analyze-login-form",
            host=None,
            crs_rule_id=942100,
            reason="FP test",
            active=True,
            created_by="test",
        )
    )
    db_session.commit()

    paths = write_waf_exports(db_session, settings)
    crs = Path(paths["crs-setup-generated.conf"]).read_text(encoding="utf-8")
    assert "inbound_anomaly_score_threshold=5" in crs
    assert "id:1000900110" in crs
    assert "id:900110" not in crs  # must not rewrite Phase A static id
    assert "id:901110" not in crs  # must not collide with CRS REQUEST-901-*

    excl = Path(paths["bastion-exclusions-generated.conf"]).read_text(encoding="utf-8")
    assert "SecRuleRemoveById 942100" in excl

    engine = Path(paths["engine-mode-generated.conf"]).read_text(encoding="utf-8")
    assert "SecRuleEngine On" in engine

    # Phase A static files are not under exports
    assert not (tmp_path / "exports" / "crs-setup.conf").exists()
    assert not (tmp_path / "exports" / "waf-basic.conf").exists()


def test_ip_deny_promotes_permanent_not_single_temp(db_session, tmp_path):
    settings = _settings(tmp_path)
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
    db_session.add(
        SecurityBan(
            target_type="ip",
            target="203.0.113.10",
            reason="once",
            permanent=False,
            created_by="test",
        )
    )
    db_session.add(
        SecurityBan(
            target_type="ip",
            target="203.0.113.50",
            reason="perm",
            permanent=True,
            created_by="test",
        )
    )
    db_session.commit()

    promoted = list_promoted_deny_ips(db_session, min_occurrences=3)
    assert "203.0.113.50" in promoted
    assert "203.0.113.10" not in promoted

    write_waf_exports(db_session, settings)
    deny = (tmp_path / "exports" / "waf-ip-deny.conf").read_text(encoding="utf-8")
    assert "deny 203.0.113.50;" in deny
    assert "203.0.113.10" not in deny


def test_ip_deny_promotes_after_repeated_bans(db_session):
    for _ in range(3):
        db_session.add(
            SecurityBan(
                target_type="ip",
                target="198.51.100.7",
                reason="repeat",
                permanent=False,
                created_by="test",
            )
        )
    # Lift previous so only one "active", but history count = 3
    bans = db_session.query(SecurityBan).filter_by(target="198.51.100.7").all()
    for b in bans[:-1]:
        b.lifted_at = bans[-1].banned_at
    db_session.commit()

    promoted = list_promoted_deny_ips(db_session, min_occurrences=3)
    assert "198.51.100.7" in promoted
    assert "deny 198.51.100.7;" in render_ip_deny_conf(promoted, min_occurrences=3)


def test_apply_restores_on_validate_failure(db_session, tmp_path):
    settings = _settings(tmp_path)
    db_session.add(
        WafProfile(
            name="Production",
            mode="on",
            anomaly_threshold=5,
            is_active=True,
            created_by="test",
        )
    )
    db_session.commit()
    write_waf_exports(db_session, settings)
    good = (tmp_path / "exports" / "modsecurity" / "engine-mode-generated.conf").read_text(
        encoding="utf-8"
    )
    assert "SecRuleEngine On" in good

    db_session.query(WafProfile).one().mode = "detection_only"
    db_session.commit()

    def fail_validate(_settings):
        return False, "nginx: [emerg] fake failure"

    result = apply_waf_exports(db_session, settings, validate=fail_validate)
    assert result["ok"] is False
    assert "fake failure" in (result["error"] or "")
    restored = (
        tmp_path / "exports" / "modsecurity" / "engine-mode-generated.conf"
    ).read_text(encoding="utf-8")
    assert "SecRuleEngine On" in restored


def test_write_waf_exports_preserves_last_apply_metadata(db_session, tmp_path):
    settings = _settings(tmp_path)
    db_session.add(
        WafProfile(
            name="Production",
            mode="on",
            anomaly_threshold=5,
            is_active=True,
            created_by="test",
        )
    )
    db_session.commit()
    write_waf_exports(db_session, settings)
    record_waf_apply_metadata(
        settings,
        actor="admin@example.com",
        nginx_t_ok=True,
        nginx_t_detail="nginx -t ok",
    )
    db_session.query(WafProfile).one().anomaly_threshold = 6
    db_session.commit()
    write_waf_exports(db_session, settings)
    status = read_effective_status(settings)
    assert status["last_apply_by"] == "admin@example.com"
    assert status["last_apply_nginx_t_ok"] is True
    assert status["anomaly_threshold"] == 6


def test_record_waf_apply_metadata_after_success(db_session, tmp_path):
    settings = _settings(tmp_path)
    db_session.add(
        WafProfile(
            name="Production",
            mode="on",
            anomaly_threshold=5,
            is_active=True,
            created_by="test",
        )
    )
    db_session.commit()
    write_waf_exports(db_session, settings)
    record_waf_apply_metadata(
        settings,
        actor="ops@vince",
        nginx_t_ok=True,
        nginx_t_detail="nginx: configuration file test is ok",
    )
    status = read_effective_status(settings)
    assert status["last_apply_at"]
    assert status["last_apply_by"] == "ops@vince"
    assert status["last_apply_nginx_t_ok"] is True
    assert "ok" in status["last_apply_nginx_t_detail"]


def test_read_effective_status_legacy_export_file_mtime(db_session, tmp_path):
    settings = _settings(tmp_path)
    mod_dir = tmp_path / "exports" / "modsecurity"
    mod_dir.mkdir(parents=True)
    (mod_dir / "waf-effective-status.json").write_text(
        '{"mode":"on","anomaly_threshold":5,"profile_name":"Production"}',
        encoding="utf-8",
    )
    status = read_effective_status(settings)
    assert status["present"] is True
    assert "last_apply_at" not in status
    assert status.get("export_file_mtime")


def test_render_helpers_detection_only():
    profile = WafProfile(name="x", mode="detection_only", anomaly_threshold=7)
    assert "DetectionOnly" in render_engine_mode_generated(profile)
    assert "threshold=7" in render_crs_setup_generated(profile)
    excl = WafExclusion(
        crs_rule_id=1, reason="r", uri_pattern="/x", active=True
    )
    assert "SecRuleRemoveById 1" in render_exclusions_generated([excl])
