"""Effective per-app WAF shield — nginx reality, not DB profile."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from app.bastion.nginx_waf_export import MODE_DETECTION, MODE_OFF, MODE_ON
from app.bastion.waf_app_protection import (
    access_mode_waf_family,
    app_waf_protection,
    apps_waf_protection_by_slug,
    family_protection_effective,
    read_family_connector_on,
)
from app.sso_settings import Settings


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        exports_dir=str(tmp_path / "exports"),
        database_url=f"sqlite:///{tmp_path / 't.db'}",
    )


def _write_switch(settings: Settings, family: str, *, on: bool) -> None:
    name = {
        "portal": "modsecurity-portal-switch.conf",
        "subdomain": "modsecurity-subdomain-switch.conf",
        "public": "modsecurity-public-switch.conf",
    }[family]
    path = Path(settings.exports_dir) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    state = "on" if on else "off"
    path.write_text(
        f"# test\nmodsecurity {state};\n",
        encoding="utf-8",
    )


def _active(*, mode: str, stale: bool = False, verifiable: bool = True) -> dict:
    fam = {
        "family": "subdomain",
        "sec_rule_engine": mode,
        "engine_mode_generated_loaded": True,
    }
    return {
        "verifiable": verifiable,
        "stale": stale,
        "families": {
            "portal": {**fam, "family": "portal"},
            "subdomain": {**fam, "family": "subdomain"},
            "public": {**fam, "family": "public"},
        },
        "generated_at": (
            datetime.now(timezone.utc) - timedelta(hours=2 if stale else 0)
        ).isoformat(),
    }


def test_access_mode_family_mapping():
    assert access_mode_waf_family("subdomain_proxy") == "subdomain"
    assert access_mode_waf_family("public_proxy") == "public"
    assert access_mode_waf_family("legacy_path_proxy") == "portal"
    assert access_mode_waf_family("sso_gate") is None
    assert access_mode_waf_family("sso") is None  # legacy → sso_gate


def test_connector_on_from_switch_export(tmp_path: Path):
    settings = _settings(tmp_path)
    assert read_family_connector_on(settings, "subdomain") is False
    _write_switch(settings, "subdomain", on=True)
    assert read_family_connector_on(settings, "subdomain") is True
    _write_switch(settings, "subdomain", on=False)
    assert read_family_connector_on(settings, "subdomain") is False


def test_family_effective_requires_connector_and_engine(tmp_path: Path):
    settings = _settings(tmp_path)
    active = _active(mode=MODE_ON)
    assert family_protection_effective(
        settings, "subdomain", active=active
    )["protected"] is False
    _write_switch(settings, "subdomain", on=True)
    ok = family_protection_effective(settings, "subdomain", active=active)
    assert ok["protected"] is True
    assert ok["mode"] == MODE_ON


def test_family_not_effective_when_engine_off(tmp_path: Path):
    settings = _settings(tmp_path)
    _write_switch(settings, "subdomain", on=True)
    status = family_protection_effective(
        settings, "subdomain", active=_active(mode=MODE_OFF)
    )
    assert status["protected"] is False
    assert status["reason"] == "engine_off"


def test_family_not_effective_when_snapshot_stale(tmp_path: Path):
    settings = _settings(tmp_path)
    _write_switch(settings, "portal", on=True)
    status = family_protection_effective(
        settings, "portal", active=_active(mode=MODE_DETECTION, stale=True)
    )
    assert status["protected"] is False
    assert status["reason"] == "snapshot_unusable"


def test_sso_gate_never_protected(tmp_path: Path):
    settings = _settings(tmp_path)
    _write_switch(settings, "portal", on=True)
    app = SimpleNamespace(slug="dolibarr", enabled=True, access_mode="sso_gate")
    status = app_waf_protection(app, settings, active=_active(mode=MODE_ON))
    assert status["protected"] is False
    assert status["reason"] == "no_proxy_family"


def test_subdomain_app_protected_when_effective(tmp_path: Path):
    settings = _settings(tmp_path)
    _write_switch(settings, "subdomain", on=True)
    app = SimpleNamespace(slug="transfer", enabled=True, access_mode="subdomain_proxy")
    status = app_waf_protection(
        app, settings, active=_active(mode=MODE_DETECTION)
    )
    assert status["protected"] is True
    assert "DetectionOnly" in status["title"]


def test_disabled_app_not_protected(tmp_path: Path):
    settings = _settings(tmp_path)
    _write_switch(settings, "subdomain", on=True)
    app = SimpleNamespace(slug="x", enabled=False, access_mode="subdomain_proxy")
    assert app_waf_protection(app, settings, active=_active(mode=MODE_ON))[
        "protected"
    ] is False


def test_apps_map_caches_family(tmp_path: Path, monkeypatch):
    settings = _settings(tmp_path)
    _write_switch(settings, "subdomain", on=True)
    snap = _active(mode=MODE_ON)
    monkeypatch.setattr(
        "app.bastion.waf_app_protection.read_nginx_waf_reality",
        lambda settings=None, snapshot_path=None: snap,
    )
    apps = [
        SimpleNamespace(slug="a", enabled=True, access_mode="subdomain_proxy"),
        SimpleNamespace(slug="b", enabled=True, access_mode="subdomain_proxy"),
        SimpleNamespace(slug="c", enabled=True, access_mode="sso_gate"),
    ]
    by_slug = apps_waf_protection_by_slug(apps, settings)
    assert by_slug["a"]["protected"] is True
    assert by_slug["b"]["protected"] is True
    assert by_slug["c"]["protected"] is False
