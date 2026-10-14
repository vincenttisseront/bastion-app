"""CrushFTP robotic login URL: prefer admin API, never public SSO FQDN."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.bastion.drivers.generic import public_host_binding_headers
from app.robotic.impersonate_service import _crushftp_login_base_url


def test_crushftp_login_prefers_admin_api_over_public_upstream():
    app = SimpleNamespace(
        access_mode="subdomain_proxy",
        public_fqdn="transfer.example.com",
        upstream_url="https://transfer.example.com/",
        crushftp_admin_base_url="https://10.20.0.106:8080/",
    )
    settings = SimpleNamespace(portal_domain="portal.example.com")
    out = _crushftp_login_base_url(app, settings, MagicMock())
    assert out == "https://10.20.0.106:8080/"
    headers = public_host_binding_headers(app, out)
    assert headers.get("Host") == "transfer.example.com"


def test_crushftp_login_uses_internal_upstream_when_no_admin():
    app = SimpleNamespace(
        access_mode="subdomain_proxy",
        public_fqdn="transfer.example.com",
        upstream_url="https://10.20.0.106/",
        crushftp_admin_base_url=None,
    )
    settings = SimpleNamespace(portal_domain="portal.example.com")
    out = _crushftp_login_base_url(app, settings, MagicMock())
    assert out == "https://10.20.0.106/"


def test_crushftp_login_rejects_public_only_urls():
    app = SimpleNamespace(
        access_mode="subdomain_proxy",
        public_fqdn="transfer.example.com",
        upstream_url="https://transfer.example.com/",
        crushftp_admin_base_url="https://transfer.example.com/",
    )
    settings = SimpleNamespace(portal_domain="portal.example.com")
    with pytest.raises(ValueError, match="URL interne"):
        _crushftp_login_base_url(app, settings, MagicMock())
