"""Per-app upstream TLS verify option."""

from __future__ import annotations

from types import SimpleNamespace

from app.bastion.nginx_public_proxy_export import generate_public_proxy_server_block
from app.bastion.nginx_subdomain_export import generate_subdomain_server_block
from app.bastion.upstream_tls import (
    nginx_proxy_ssl_verify_directive,
    resolve_upstream_tls_verify,
)
from app.sso_settings import Settings


def test_resolve_upstream_tls_verify_default_off():
    assert resolve_upstream_tls_verify(None) is False
    assert resolve_upstream_tls_verify(SimpleNamespace()) is False
    assert resolve_upstream_tls_verify(SimpleNamespace(upstream_tls_verify=False)) is False
    assert resolve_upstream_tls_verify(SimpleNamespace(upstream_tls_verify=True)) is True


def test_nginx_proxy_ssl_verify_directive():
    assert "off" in nginx_proxy_ssl_verify_directive(False)
    assert "on" in nginx_proxy_ssl_verify_directive(True)


def test_subdomain_nginx_respects_upstream_tls_verify():
    settings = Settings(portal_domain="portal.example.fr")
    app = SimpleNamespace(
        slug="grommunio",
        label="Grommunio",
        access_mode="subdomain_proxy",
        public_fqdn="grommunio.example.fr",
        upstream_url="https://172.24.10.104/",
        realm_slug="portal",
        allow_activesync=True,
        upstream_tls_verify=False,
    )
    block = generate_subdomain_server_block(app, settings)
    assert "proxy_ssl_verify off;" in block
    assert "proxy_ssl_verify on;" not in block

    app.upstream_tls_verify = True
    block_on = generate_subdomain_server_block(app, settings)
    assert "proxy_ssl_verify on;" in block_on


def test_public_proxy_nginx_respects_upstream_tls_verify():
    app = SimpleNamespace(
        slug="teleport",
        label="Teleport",
        access_mode="public_proxy",
        public_fqdn="teleport.example.fr",
        upstream_url="https://10.0.0.5:3080/",
        upstream_tls_verify=True,
    )
    block = generate_public_proxy_server_block(app)
    assert "proxy_ssl_verify on;" in block
