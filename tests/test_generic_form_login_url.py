"""generic_form login URL: rewrite public FQDN → upstream (bypass SSO auth_request)."""

from __future__ import annotations

from types import SimpleNamespace

from app.robotic.impersonate_service import _generic_form_login_url


def test_generic_form_login_url_rewrites_public_host_to_upstream():
    app = SimpleNamespace(
        login_form_url="https://grommunio.ar-systems.fr/web/",
        access_mode="subdomain_proxy",
        public_fqdn="grommunio.ar-systems.fr",
        upstream_url="https://172.24.0.60/",
    )
    out = _generic_form_login_url(app)
    assert out == "https://172.24.0.60/web/"


def test_generic_form_login_url_keeps_internal_host():
    app = SimpleNamespace(
        login_form_url="https://172.24.0.50/index.php?mainmenu=home",
        access_mode="subdomain_proxy",
        public_fqdn="dolibarr.ar-systems.fr",
        upstream_url="https://172.24.0.50/",
    )
    out = _generic_form_login_url(app)
    assert out == "https://172.24.0.50/index.php?mainmenu=home"


def test_generic_form_login_url_unchanged_without_upstream():
    app = SimpleNamespace(
        login_form_url="https://dolibarr.ar-systems.fr/index.php",
        access_mode="subdomain_proxy",
        public_fqdn="dolibarr.ar-systems.fr",
        upstream_url="",
    )
    out = _generic_form_login_url(app)
    assert out == "https://dolibarr.ar-systems.fr/index.php"


def test_generic_form_login_url_unchanged_outside_subdomain_proxy():
    app = SimpleNamespace(
        login_form_url="https://grommunio.ar-systems.fr/web/",
        access_mode="path_proxy",
        public_fqdn="grommunio.ar-systems.fr",
        upstream_url="https://172.24.0.60/",
    )
    out = _generic_form_login_url(app)
    assert out == "https://grommunio.ar-systems.fr/web/"
