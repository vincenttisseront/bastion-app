"""Tests for IHM ModSecurity reactivation + smoke rollback."""

from __future__ import annotations

from pathlib import Path

from app.bastion.nginx_waf_export import MODE_DETECTION, MODE_OFF, MODE_ON
from app.bastion.waf_reactivation import (
    reactivate_engine,
    reactivate_subdomain_engine,
    read_arm_state,
    read_subdomain_armed,
    render_portal_switch,
    render_public_switch,
    render_subdomain_switch,
    smoke_portal_probes,
    smoke_subdomain_probes,
    write_arm_state,
)
from app.models import App, WafProfile
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


def test_render_subdomain_and_public_switches():
    assert "Subdomain" in render_subdomain_switch(enabled=True)
    assert "modsecurity on;" in render_subdomain_switch(enabled=True)
    assert "modsecurity off;" in render_subdomain_switch(enabled=False)
    assert "Public proxy" in render_public_switch(enabled=True)
    assert "modsecurity on;" in render_public_switch(enabled=True)


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
    calls: list[tuple[str, str | None]] = []

    def fake_probe(url, **kwargs):
        calls.append((url, kwargs.get("host")))
        return {"ok": True, "status": 200, "url": url, "reason": "ok", "host": kwargs.get("host")}

    monkeypatch.setattr("app.bastion.waf_reactivation._http_probe", fake_probe)
    out = smoke_portal_probes(settings)
    assert out["ok"] is True
    assert len(out["probes"]) >= 4
    assert any("8080/auth/login" in u for u, _h in calls)
    # Must not probe :8080 with Host=nginx (unknown → 403).
    assert all(h == "portal.example.fr" for u, h in calls if "nginx:8080" in u)
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


def _seed_portal_armed(db_session, tmp_path: Path) -> Settings:
    settings = _settings(tmp_path)
    db_session.add(
        WafProfile(
            name="Production",
            mode=MODE_DETECTION,
            anomaly_threshold=5,
            is_active=True,
            created_by="test",
        )
    )
    db_session.commit()
    write_arm_state(settings, {"armed": True, "family": "portal", "target_mode": MODE_DETECTION})
    return settings


def test_reactivate_subdomain_requires_portal_armed(db_session, tmp_path: Path):
    settings = _settings(tmp_path)
    db_session.add(
        App(
            slug="doli",
            label="Doli",
            public_fqdn="doli.example.fr",
            access_mode="subdomain_proxy",
            enabled=True,
            upstream_url="http://127.0.0.1:8080",
        )
    )
    db_session.commit()
    result = reactivate_subdomain_engine(
        db_session,
        settings,
        actor="admin",
        confirm=True,
        sync_reload=lambda _s: (True, "ok"),
        smoke=lambda _db, _s: {"ok": True, "probes": [], "failed": []},
    )
    assert result["ok"] is False
    assert "portal" in (result.get("error") or "").lower()


def test_reactivate_subdomain_success(db_session, tmp_path: Path):
    settings = _seed_portal_armed(db_session, tmp_path)
    db_session.add(
        App(
            slug="doli",
            label="Doli",
            public_fqdn="doli.example.fr",
            access_mode="subdomain_proxy",
            enabled=True,
            upstream_url="http://127.0.0.1:8080",
        )
    )
    db_session.commit()

    result = reactivate_subdomain_engine(
        db_session,
        settings,
        actor="admin",
        confirm=True,
        sync_reload=lambda _s: (True, "ok"),
        smoke=lambda _db, _s: {"ok": True, "probes": [{"ok": True}], "failed": []},
    )
    assert result["ok"] is True
    assert read_subdomain_armed(settings) is True
    switch = (tmp_path / "exports" / "modsecurity-subdomain-switch.conf").read_text(
        encoding="utf-8"
    )
    assert "modsecurity on;" in switch
    engine = (
        tmp_path / "exports" / "modsecurity" / "engine-subdomain-mode-generated.conf"
    ).read_text(encoding="utf-8")
    assert "DetectionOnly" in engine


def test_reactivate_subdomain_smoke_failure_rolls_back(db_session, tmp_path: Path):
    settings = _seed_portal_armed(db_session, tmp_path)
    db_session.add(
        App(
            slug="doli",
            label="Doli",
            public_fqdn="doli.example.fr",
            access_mode="subdomain_proxy",
            enabled=True,
            upstream_url="http://127.0.0.1:8080",
        )
    )
    db_session.commit()

    result = reactivate_subdomain_engine(
        db_session,
        settings,
        actor="admin",
        confirm=True,
        sync_reload=lambda _s: (True, "ok"),
        smoke=lambda _db, _s: {
            "ok": False,
            "probes": [{"url": "http://nginx:8080/", "ok": False, "status": 500}],
            "failed": [{"url": "http://nginx:8080/", "status": 500}],
        },
    )
    assert result["ok"] is False
    assert result["rolled_back"] is True
    assert read_subdomain_armed(settings) is False
    switch = (tmp_path / "exports" / "modsecurity-subdomain-switch.conf").read_text(
        encoding="utf-8"
    )
    assert "modsecurity off;" in switch
