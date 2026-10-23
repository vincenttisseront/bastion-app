"""Promotion readiness + virtual-patch pack toggles."""

from __future__ import annotations

from app.bastion.nginx_waf_export import render_virtual_patches_enabled
from app.bastion.waf_promotion import evaluate_promotion_readiness
from app.bastion.waf_virtual_patches import (
    build_virtual_patches_panel,
    render_virtual_patches_enabled_conf,
)
from app.models import WafProfile
from app.sso_settings import Settings


def test_virtual_patches_conf_include_when_enabled():
    text = render_virtual_patches_enabled_conf(php2shell_enabled=True)
    assert "Include /etc/nginx/modsecurity/bastion-virtual-patches.conf" in text
    assert "disabled" not in text.lower() or "Pack php2shell enabled" in text


def test_virtual_patches_conf_stub_when_disabled():
    text = render_virtual_patches_enabled_conf(php2shell_enabled=False)
    assert "Include /etc/nginx/modsecurity/bastion-virtual-patches.conf" not in text
    assert "disabled" in text.lower()


def test_render_virtual_patches_from_profile():
    profile = WafProfile(name="P", mode="on", patch_php2shell_enabled=False)
    text = render_virtual_patches_enabled(profile)
    assert "Include /etc/nginx/modsecurity/bastion-virtual-patches.conf" not in text


def test_promotion_not_applicable_when_disarmed(tmp_path):
    settings = Settings(
        portal_domain="portal.example.com",
        exports_dir=str(tmp_path / "exports"),
    )  # type: ignore[call-arg]
    (tmp_path / "exports" / "modsecurity").mkdir(parents=True)
    panel = evaluate_promotion_readiness(settings, family="portal")
    assert panel["status"] == "not_applicable"
    assert panel["can_promote"] is False
    assert panel["auto_promote"] is False


def test_virtual_patches_panel_lists_php2shell(db_session):
    settings = Settings(
        portal_domain="portal.example.com",
        exports_dir="/tmp/waf-vp",
    )  # type: ignore[call-arg]
    profile = WafProfile(name="P", mode="on", patch_php2shell_enabled=True)
    panel = build_virtual_patches_panel(db_session, settings, profile)
    assert panel["packs"]
    assert panel["packs"][0]["id"] == "php2shell"
    assert panel["packs"][0]["enabled"] is True
