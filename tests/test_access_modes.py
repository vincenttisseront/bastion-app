"""Tests for application access mode helpers."""

from types import SimpleNamespace

import pytest

from app.access_modes import (
    app_launch_url,
    normalize_access_mode,
    validate_app_access_fields,
)
from app.admin.export import generate_nginx_apps_conf
from app.models import App


def test_normalize_legacy_modes():
    assert normalize_access_mode("sso") == "sso_gate"
    assert normalize_access_mode("subdomain") == "subdomain_proxy"
    assert normalize_access_mode("sso_gate") == "sso_gate"


def test_validate_subdomain_requires_fqdn():
    errors = validate_app_access_fields("subdomain_proxy", "http://127.0.0.1:8080", None)
    assert "public_fqdn" in errors


def test_validate_subdomain_rejects_upstream_path():
    errors = validate_app_access_fields(
        "subdomain_proxy", "https://10.0.0.50/web/", "webmail.example.fr"
    )
    assert "upstream_url" in errors
    assert "/web" in errors["upstream_url"]
    ok = validate_app_access_fields(
        "subdomain_proxy", "https://10.0.0.50/", "webmail.example.fr"
    )
    assert ok == {}


def test_app_launch_url_subdomain_uses_login_entry_path():
    app = SimpleNamespace(
        access_mode="subdomain_proxy",
        upstream_url="https://10.0.0.50/",
        public_fqdn="webmail.example.fr",
        slug="grommunio",
        robotic_driver=None,
        login_form_url="https://webmail.example.fr/web/?logon",
    )
    assert app_launch_url(app) == "https://webmail.example.fr/web/"


def test_app_launch_url_wikijs_sso_entry_keeps_login_without_slash():
    """Portal tile must open /login (Bypass Login Screen), not /login/."""
    app = SimpleNamespace(
        access_mode="subdomain_proxy",
        upstream_url="https://10.0.31.112/",
        public_fqdn="wikijs.ar-systems.fr",
        slug="wikijs",
        robotic_driver=None,
        login_form_url="https://wikijs.ar-systems.fr/login",
    )
    assert app_launch_url(app) == "https://wikijs.ar-systems.fr/login"


def test_normalize_sso_bridge_and_app_oidc_requires_entry():
    from app.bastion.bastion_fields import normalize_sso_bridge
    from app.web.pages import _validate_auth_fields

    assert normalize_sso_bridge(None) == "trusted_headers"
    assert normalize_sso_bridge("APP_OIDC") == "app_oidc"
    assert normalize_sso_bridge("nope") == "trusted_headers"

    missing = _validate_auth_fields(
        "subdomain_proxy",
        "sso",
        "",
        "username",
        "password",
        "POST",
        "",
        sso_bridge="app_oidc",
    )
    assert "login_form_url" in missing

    ok = _validate_auth_fields(
        "subdomain_proxy",
        "sso",
        "https://app.example.com/login",
        "username",
        "password",
        "POST",
        "",
        sso_bridge="app_oidc",
    )
    assert ok == {}

    trusted_ok = _validate_auth_fields(
        "subdomain_proxy",
        "sso",
        "",
        "username",
        "password",
        "POST",
        "",
        sso_bridge="trusted_headers",
    )
    assert trusted_ok == {}


def test_validate_public_proxy_requires_fqdn():
    errors = validate_app_access_fields("public_proxy", "http://127.0.0.1:8080", "")
    assert "public_fqdn" in errors


def test_app_launch_url_sso_gate():
    app = SimpleNamespace(
        access_mode="sso_gate",
        upstream_url="https://wiki.example.fr/",
        public_fqdn=None,
        slug="wiki",
    )
    assert app_launch_url(app) == "https://wiki.example.fr/"


def test_app_launch_url_legacy_proxy():
    app = SimpleNamespace(
        access_mode="legacy_path_proxy",
        upstream_url="http://127.0.0.1:8080/",
        public_fqdn=None,
        slug="legacy-app",
    )
    assert app_launch_url(app) == "/proxy/legacy-app/"


def test_generate_nginx_apps_conf_skips_sso_gate(db_session):
    db_session.add(
        App(
            slug="wiki",
            label="Wiki",
            upstream_url="https://wiki.example.fr/",
            access_mode="sso_gate",
            enabled=True,
        )
    )
    db_session.commit()
    conf = generate_nginx_apps_conf(db_session)
    assert "SSO Gate" in conf
    assert "location /proxy/wiki/" not in conf
