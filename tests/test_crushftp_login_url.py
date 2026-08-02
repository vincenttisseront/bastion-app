"""CrushFTP robotic login URL: upstream + Host=FQDN (bypass SSO auth_request)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.bastion.drivers.generic import public_host_binding_headers
from app.robotic.impersonate_service import _crushftp_login_base_url


def test_crushftp_login_base_url_prefers_upstream_in_subdomain():
    app = SimpleNamespace(
        access_mode="subdomain_proxy",
        public_fqdn="transfer.ar-systems.fr",
        upstream_url="https://172.24.0.106/",
    )
    settings = SimpleNamespace()
    db = MagicMock()
    with patch(
        "app.portal_settings_service.get_subdomain_sso_enabled",
        return_value=True,
    ):
        out = _crushftp_login_base_url(app, settings, db)
    assert out == "https://172.24.0.106/"
    headers = public_host_binding_headers(app, out)
    assert headers.get("Host") == "transfer.ar-systems.fr"


def test_crushftp_login_base_url_falls_back_to_upstream_without_fqdn():
    app = SimpleNamespace(
        access_mode="path_proxy",
        public_fqdn=None,
        upstream_url="https://crush.internal/",
    )
    settings = SimpleNamespace()
    db = MagicMock()
    with patch(
        "app.portal_settings_service.get_subdomain_sso_enabled",
        return_value=False,
    ):
        out = _crushftp_login_base_url(app, settings, db)
    assert out == "https://crush.internal/"
