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
