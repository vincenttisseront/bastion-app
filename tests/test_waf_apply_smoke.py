"""Apply WAF must smoke-test when engine is armed (incident On → /auth/login 500)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from app.bastion.nginx_waf_export import MODE_DETECTION, MODE_ON, ensure_active_profile
from app.models import WafProfile
from app.security.waf import service as waf_service
from app.sso_settings import Settings


def _settings(tmp_path: Path) -> Settings:
    exports = tmp_path / "exports"
    exports.mkdir(parents=True)
    return Settings(
        portal_domain="portal.example.fr",
        exports_dir=str(exports),
        portal_data_dir=str(tmp_path / "data"),
        nginx_app_logs_dir=str(tmp_path / "nginx-logs"),
        vault_portal_internal_token="test",
    )  # type: ignore[call-arg]


def test_apply_rolls_back_when_armed_and_smoke_fails(db_session, tmp_path: Path):
    settings = _settings(tmp_path)
    db_session.add(
        WafProfile(
            name="Production",
            mode=MODE_ON,
            anomaly_threshold=5,
            is_active=True,
            created_by="test",
        )
    )
    db_session.commit()

    arm = tmp_path / "exports" / "modsecurity" / "waf-engine-arm.json"
    arm.parent.mkdir(parents=True, exist_ok=True)
    arm.write_text('{"armed": true, "family": "portal"}', encoding="utf-8")

    with patch(
        "app.security.waf.service.apply_waf_exports",
        return_value={"ok": True, "paths": {}, "validate_skipped": True},
    ), patch(
        "app.security.waf.service.restore_waf_exports_previous",
        return_value=True,
    ) as restore, patch(
        "app.bastion.waf_reactivation.wait_for_nginx_edge",
        return_value={"ok": True},
    ), patch(
        "app.bastion.waf_reactivation.wait_for_portal_engine_mode",
        return_value={"ok": True, "mode": MODE_ON},
    ), patch(
        "app.bastion.waf_reactivation.smoke_portal_probes",
        return_value={
            "ok": False,
            "failed": [{"url": "/auth/login", "status": 500}],
            "failed_summary": "/auth/login → HTTP 500",
        },
    ), patch(
        "app.bastion.waf_reactivation.sync_and_reload",
        return_value=(True, "watcher"),
    ):
        result = waf_service.apply_waf(db_session, settings, actor="admin")

    assert result["ok"] is False
    assert result["rolled_back"] is True
    restore.assert_called_once()
    assert "500" in (result.get("error") or "")


def test_apply_rolls_back_when_engine_mode_not_reached(db_session, tmp_path: Path):
    settings = _settings(tmp_path)
    db_session.add(
        WafProfile(
            name="Production",
            mode=MODE_ON,
            anomaly_threshold=5,
            is_active=True,
            created_by="test",
        )
    )
    db_session.commit()

    arm = tmp_path / "exports" / "modsecurity" / "waf-engine-arm.json"
    arm.parent.mkdir(parents=True, exist_ok=True)
    arm.write_text('{"armed": true}', encoding="utf-8")

    with patch(
        "app.security.waf.service.apply_waf_exports",
        return_value={"ok": True, "paths": {}, "validate_skipped": True},
    ), patch(
        "app.security.waf.service.restore_waf_exports_previous",
        return_value=True,
    ) as restore, patch(
        "app.bastion.waf_reactivation.wait_for_nginx_edge",
        return_value={"ok": True},
    ), patch(
        "app.bastion.waf_reactivation.wait_for_portal_engine_mode",
        return_value={"ok": False, "mode": MODE_DETECTION},
    ) as engine_wait, patch(
        "app.bastion.waf_reactivation.smoke_portal_probes",
    ) as smoke, patch(
        "app.bastion.waf_reactivation.sync_and_reload",
        return_value=(True, "watcher"),
    ):
        result = waf_service.apply_waf(db_session, settings, actor="admin")

    assert result["ok"] is False
    assert result["rolled_back"] is True
    engine_wait.assert_called_once_with(settings, MODE_ON)
    smoke.assert_not_called()
    restore.assert_called_once()


def test_apply_skips_smoke_when_disarmed(db_session, tmp_path: Path):
    settings = _settings(tmp_path)
    ensure_active_profile(db_session)
    profile = db_session.query(WafProfile).filter_by(is_active=True).one()
    profile.mode = MODE_DETECTION
    db_session.commit()

    arm = tmp_path / "exports" / "modsecurity" / "waf-engine-arm.json"
    arm.parent.mkdir(parents=True, exist_ok=True)
    arm.write_text('{"armed": false}', encoding="utf-8")

    with patch(
        "app.security.waf.service.apply_waf_exports",
        return_value={"ok": True, "paths": {}, "validate_skipped": True},
    ), patch(
        "app.bastion.waf_reactivation.smoke_portal_probes",
    ) as smoke:
        result = waf_service.apply_waf(db_session, settings, actor="admin")

    assert result["ok"] is True
    smoke.assert_not_called()
