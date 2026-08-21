"""Tests for IHM ModSecurity reactivation + smoke rollback."""

from __future__ import annotations

from pathlib import Path

from app.bastion.nginx_waf_export import MODE_DETECTION, MODE_OFF, MODE_ON
from app.bastion.waf_reactivation import (
    reactivate_engine,
    read_arm_state,
    render_portal_switch,
    smoke_portal_probes,
)
from app.models import WafProfile
from app.sso_settings import Settings


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        portal_domain="portal.example.fr",
        sso_portal_default_realm_slug="ar-systems",
        exports_dir=str(tmp_path / "exports"),
        portal_data_dir=str(tmp_path / "data"),
        vault_portal_internal_token="test-secret",
    )  # type: ignore[call-arg]


def test_render_portal_switch():
    assert "modsecurity on;" in render_portal_switch(enabled=True)
    assert "modsecurity off;" in render_portal_switch(enabled=False)


def test_reactivate_requires_confirm(db_session, tmp_path: Path):
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
    result = reactivate_engine(
        db_session,
        settings,
        actor="admin",
        confirm=False,
        sync_reload=lambda _s: (True, "ok"),
        smoke=lambda _s: {"ok": True, "probes": [], "failed": []},
    )
    assert result["ok"] is False
    assert result["rolled_back"] is False


def test_reactivate_smoke_failure_rolls_back(db_session, tmp_path: Path):
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

    result = reactivate_engine(
        db_session,
        settings,
        actor="admin",
        confirm=True,
        sync_reload=lambda _s: (True, "nginx -t ok"),
        smoke=lambda _s: {
            "ok": False,
            "probes": [{"url": "/auth/login", "ok": False, "status": 500}],
            "failed": [{"url": "/auth/login", "status": 500}],
        },
    )
    assert result["ok"] is False
    assert result["rolled_back"] is True
    arm = read_arm_state(settings)
    assert arm.get("armed") is False
    profile = db_session.query(WafProfile).filter_by(is_active=True).one()
    assert profile.mode == MODE_OFF
    switch = (tmp_path / "exports" / "modsecurity-portal-switch.conf").read_text(
        encoding="utf-8"
    )
    assert "modsecurity off;" in switch


def test_sync_and_reload_without_compose_delegates_to_watcher(tmp_path: Path):
    settings = _settings(tmp_path)
    (tmp_path / "exports" / "modsecurity").mkdir(parents=True)
    from app.bastion.waf_reactivation import sync_and_reload, write_arm_state

    write_arm_state(settings, {"armed": True, "family": "portal"})
    ok, detail = sync_and_reload(settings)
    assert ok is True
    assert "watcher" in detail.lower()


def test_reactivate_success_arms_detection_only(db_session, tmp_path: Path):
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

    result = reactivate_engine(
        db_session,
        settings,
        actor="admin",
        confirm=True,
        sync_reload=lambda _s: (True, "ok"),
        smoke=lambda _s: {"ok": True, "probes": [{"ok": True}], "failed": []},
    )
    assert result["ok"] is True
    assert result["mode"] == MODE_DETECTION
    arm = read_arm_state(settings)
    assert arm.get("armed") is True
    assert arm.get("target_mode") == MODE_DETECTION
    profile = db_session.query(WafProfile).filter_by(is_active=True).one()
    assert profile.mode == MODE_DETECTION
    switch = (tmp_path / "exports" / "modsecurity-portal-switch.conf").read_text(
        encoding="utf-8"
    )
    assert "modsecurity on;" in switch


def test_smoke_portal_probes_structure(monkeypatch, tmp_path: Path):
    settings = _settings(tmp_path)
    calls: list[str] = []

    def fake_probe(url, **kwargs):
        calls.append(url)
        return {"ok": True, "status": 200, "url": url, "reason": "ok"}

    monkeypatch.setattr("app.bastion.waf_reactivation._http_probe", fake_probe)
    out = smoke_portal_probes(settings)
    assert out["ok"] is True
    assert len(out["probes"]) >= 4
    assert any("8080/auth/login" in u for u in calls)
    # Public HTTPS is optional — must not be required for ok
    assert any(p.get("optional") for p in out["probes"])


def test_smoke_ignores_optional_https_failure(monkeypatch, tmp_path: Path):
    settings = _settings(tmp_path)

    def fake_probe(url, **kwargs):
        if url.startswith("https://"):
            return {"ok": False, "error": "SSL", "url": url, "status": None}
        return {"ok": True, "status": 200, "url": url, "reason": "ok"}

    monkeypatch.setattr("app.bastion.waf_reactivation._http_probe", fake_probe)
    out = smoke_portal_probes(settings)
    assert out["ok"] is True
    assert out["failed"] == []


def test_smoke_fails_on_internal_login_500(monkeypatch, tmp_path: Path):
    settings = _settings(tmp_path)

    def fake_probe(url, **kwargs):
        if "/auth/login" in url and "8080" in url:
            return {
                "ok": False,
                "status": 500,
                "url": url,
                "reason": "HTTP 500",
            }
        return {"ok": True, "status": 200, "url": url, "reason": "ok"}

    monkeypatch.setattr("app.bastion.waf_reactivation._http_probe", fake_probe)
    out = smoke_portal_probes(settings)
    assert out["ok"] is False
    assert "500" in (out.get("failed_summary") or "")
