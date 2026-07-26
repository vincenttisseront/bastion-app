"""Nginx session-cookie hop: browser-reachable, never `internal;`."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
NGINX_ROOT = ROOT / "nginx"
VHOSTS = NGINX_ROOT / "vhosts"
SNIPPETS = NGINX_ROOT / "snippets"


def _location_block(text: str, path: str) -> str:
    needle = f"location = {path}"
    idx = text.index(needle)
    depth = 0
    started = False
    for i, ch in enumerate(text[idx:], start=idx):
        if ch == "{":
            depth += 1
            started = True
        elif ch == "}":
            depth -= 1
            if started and depth == 0:
                return text[idx : i + 1]
    raise AssertionError(f"unclosed location block for {path}")


def _assert_hop_public(block: str, *, label: str) -> None:
    assert "auth_request off;" in block, f"{label}: hop must disable auth_request"
    assert "internal;" not in block, f"{label}: hop must NOT be internal (browser 302)"
    assert "session-cookie-hop" in block or "proxy_pass" in block


def _render_subdomain(*, slug: str = "demoapp", fqdn: str = "demo.example.test") -> str:
    env = Environment(
        loader=FileSystemLoader([str(VHOSTS), str(NGINX_ROOT)]),
        undefined=StrictUndefined,
        autoescape=False,
    )
    tpl = env.get_template("vhost-subdomain-crushftp.conf.j2")
    return tpl.render(
        ansible_managed="test",
        vhost={
            "slug": slug,
            "fqdn": fqdn,
            "upstream_url": "https://127.0.0.1:8443/",
            "upstream_host": "127.0.0.1",
            "realm_slug": "ar-systems",
            "ssl_cert": "/etc/ssl/certs/test.pem",
            "ssl_key": "/etc/ssl/private/test.key",
        },
        nginx_ssl_cert_default="/etc/ssl/certs/test.pem",
        nginx_ssl_key_default="/etc/ssl/private/test.key",
        sso_portal_bind_host="127.0.0.1",
        sso_portal_bind_port="8000",
        portal_domain="portal.example.test",
        bastion_app_proxy_pass="https://127.0.0.1:8443",
        sso_portal_default_realm_slug="ar-systems",
        nginx_legacy_proxy_redirect_enabled=False,
        nginx_legacy_proxy_redirects=[],
    )


def _render_transfer() -> str:
    env = Environment(
        loader=FileSystemLoader([str(VHOSTS), str(NGINX_ROOT)]),
        undefined=StrictUndefined,
        autoescape=False,
    )
    tpl = env.get_template("vhost_transfer_crushftp.conf.j2")
    return tpl.render(
        ansible_managed="test",
        transfer_domain="transfer.example.test",
        transfer_backend="https://127.0.0.1:443",
        transfer_backend_ip="127.0.0.1",
        portal_domain="portal.example.test",
        bastion_app_proxy_pass="https://127.0.0.1:8443",
        ssl_certificate_path="/etc/ssl/certs/test.pem",
        ssl_certificate_key="/etc/ssl/private/test.key",
    )


def test_subdomain_template_hop_not_internal_has_auth_off():
    """Generic mock render (not tied to a real app slug)."""
    rendered = _render_subdomain()
    hop = _location_block(rendered, "/.bastion/session-cookies")
    _assert_hop_public(hop, label="subdomain-mock")


def test_subdomain_auth_still_internal_in_same_render_tree():
    snippet = (SNIPPETS / "subdomain_auth_common.conf.j2").read_text(encoding="utf-8")
    auth = _location_block(snippet, "/internal/subdomain-auth")
    assert "internal;" in auth
    assert "auth_request off;" in auth
    rendered = _render_subdomain()
    assert "include snippets/subdomain_auth_common.conf;" in rendered


def test_transfer_j2_hop_not_internal_has_auth_off():
    rendered = _render_transfer()
    hop = _location_block(rendered, "/.bastion/session-cookies")
    _assert_hop_public(hop, label="transfer-j2")
    assert re.search(r"location\s+/\s*\{", rendered)
    assert "location ~ /\\." in rendered
    assert "deny all;" in rendered


def test_transfer_reference_hop_not_internal_has_auth_off():
    text = (NGINX_ROOT / "reference-from-awx/vhost_transfer_crushftp.conf").read_text(
        encoding="utf-8"
    )
    hop = _location_block(text, "/.bastion/session-cookies")
    _assert_hop_public(hop, label="transfer-reference")


def test_subdomain_source_template_hop_contract():
    text = (VHOSTS / "vhost-subdomain-crushftp.conf.j2").read_text(encoding="utf-8")
    hop = _location_block(text, "/.bastion/session-cookies")
    _assert_hop_public(hop, label="subdomain-source")
    assert "location = /healthz" in text
    assert "auth_request /internal/subdomain-auth;" in text
    assert "include snippets/subdomain_auth_common.conf;" in text


def test_grommunio_is_in_subdomain_vhosts_list():
    defaults = (
        ROOT / "ansible/roles/sso_portal/defaults/main.yml"
    ).read_text(encoding="utf-8")
    assert "slug: grommunio" in defaults
    assert "fqdn: webmail.ar-systems.fr" in defaults
    assert "vhost-subdomain-crushftp.conf.j2" in (
        ROOT / "ansible/roles/sso_portal/tasks/nginx_vhosts.yml"
    ).read_text(encoding="utf-8")


def _nginx_t_for_rendered(server_conf: str, label: str) -> None:
    nginx = shutil.which("nginx")
    if not nginx:
        pytest.skip("nginx binary not available on this host")

    with tempfile.TemporaryDirectory(prefix=f"bastion-nginx-{label}-") as tmp:
        tmp_path = Path(tmp)
        conf_path = tmp_path / "nginx.conf"
        conf_path.write_text(
            "\n".join(["events {}", "http {", server_conf, "}", ""]),
            encoding="utf-8",
        )
        snippets = tmp_path / "snippets"
        snippets.mkdir()
        (snippets / "subdomain_auth_common.conf").write_text(
            "\n".join(
                [
                    "location = /internal/subdomain-auth {",
                    "    internal;",
                    "    auth_request off;",
                    "    return 204;",
                    "}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        adjusted = conf_path.read_text(encoding="utf-8").replace(
            "include snippets/subdomain_auth_common.conf;",
            f"include {snippets.as_posix()}/subdomain_auth_common.conf;",
        )
        adjusted = re.sub(r"^\s*ssl_certificate.*\n", "", adjusted, flags=re.M)
        adjusted = re.sub(r"^\s*ssl_certificate_key.*\n", "", adjusted, flags=re.M)
        adjusted = adjusted.replace(" ssl http2", "")
        conf_path.write_text(adjusted, encoding="utf-8")

        proc = subprocess.run(
            [nginx, "-t", "-c", str(conf_path), "-p", str(tmp_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, (
            f"nginx -t failed for {label}:\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )


def test_nginx_t_transfer_and_grommunio_renders():
    transfer = _render_transfer()
    grommunio = _render_subdomain(slug="grommunio", fqdn="webmail.ar-systems.fr")
    _nginx_t_for_rendered(transfer, "transfer")
    _nginx_t_for_rendered(grommunio, "grommunio")
