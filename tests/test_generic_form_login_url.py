"""generic_form login URL rewrite to public FQDN in subdomain mode."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.robotic.impersonate_service import _generic_form_login_url


def test_generic_form_login_url_rewrites_host_in_subdomain_mode():
    app = SimpleNamespace(
        login_form_url="https://172.24.0.50/index.php?mainmenu=home",
        access_mode="subdomain_proxy",
        public_fqdn="dolibarr.ar-systems.fr",
    )
    settings = MagicMock()
    db = MagicMock()
    with patch(
        "app.portal_settings_service.get_subdomain_sso_enabled", return_value=True
    ):
        out = _generic_form_login_url(app, settings, db)
    assert out == "https://dolibarr.ar-systems.fr/index.php?mainmenu=home"


def test_generic_form_login_url_keeps_public_host():
    app = SimpleNamespace(
        login_form_url="https://dolibarr.ar-systems.fr/index.php",
        access_mode="subdomain_proxy",
        public_fqdn="dolibarr.ar-systems.fr",
    )
    settings = MagicMock()
    db = MagicMock()
    with patch(
        "app.portal_settings_service.get_subdomain_sso_enabled", return_value=True
    ):
        out = _generic_form_login_url(app, settings, db)
    assert out == "https://dolibarr.ar-systems.fr/index.php"


def test_generic_form_login_url_unchanged_without_subdomain_sso():
    app = SimpleNamespace(
        login_form_url="https://172.24.0.50/index.php",
        access_mode="subdomain_proxy",
        public_fqdn="dolibarr.ar-systems.fr",
    )
    settings = MagicMock()
    db = MagicMock()
    with patch(
        "app.portal_settings_service.get_subdomain_sso_enabled", return_value=False
    ):
        out = _generic_form_login_url(app, settings, db)
    assert out == "https://172.24.0.50/index.php"
