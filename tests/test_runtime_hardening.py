"""v3.2 — runtime hardening probe + compose flags."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from app.security.runtime_check import check_runtime_hardening


def test_check_runtime_hardening_shape():
    result = check_runtime_hardening()
    assert "is_root" in result
    assert "read_only_fs" in result
    assert "no_new_privileges" in result
    assert "caps_dropped" in result
    assert result["runtime_status"] in ("hardened", "loose")
    assert isinstance(result["ok"], bool)


def test_hardened_when_signals_align():
    with (
        patch("app.security.runtime_check._is_root", return_value=False),
        patch("app.security.runtime_check._read_only_root_fs", return_value=True),
        patch("app.security.runtime_check._no_new_privileges", return_value=True),
        patch("app.security.runtime_check._cap_eff_emptyish", return_value=True),
    ):
        result = check_runtime_hardening()
    assert result["runtime_status"] == "hardened"
    assert result["ok"] is True
    assert result["is_root"] is False


def test_loose_when_root():
    with (
        patch("app.security.runtime_check._is_root", return_value=True),
        patch("app.security.runtime_check._read_only_root_fs", return_value=True),
        patch("app.security.runtime_check._no_new_privileges", return_value=True),
    ):
        result = check_runtime_hardening()
    assert result["runtime_status"] == "loose"
    assert result["ok"] is False


def test_compose_hardening_flags():
    root = Path(__file__).resolve().parents[1]
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    assert "no-new-privileges:true" in compose
    assert "read_only: true" in compose
    assert "cap_drop:" in compose
    assert "NET_BIND_SERVICE" in compose
    assert "SETUID" in compose
    assert "SETGID" in compose
    assert "/etc/nginx/conf.d:size=" in compose
    assert "mode=0777" in compose
    assert "/tmp:size=256M" in compose or "/tmp:size=64M" in compose
    assert "user: \"65532:65532\"" in compose
    # nginx service starts as 0:0 then entrypoint su-exec to nginx
    assert 'user: "0:0"' in compose


def test_nginx_dockerfile_seeds_tmpfs_overlay():
    root = Path(__file__).resolve().parents[1]
    df = (root / "docker/nginx/Dockerfile").read_text(encoding="utf-8")
    assert "/usr/share/bastion-nginx/seed" in df
    assert "su-exec" in df
    assert "USER root" in df
    entry = (root / "docker/nginx/docker-entrypoint.sh").read_text(encoding="utf-8")
    assert "_seed_nginx_writable_dirs" in entry
    assert "BASTION_NGINX_SEED" in entry
    assert "su-exec nginx:nginx" in entry
    assert "_nginx_as_worker" in entry
    assert "client_temp" in entry
    assert "SETUID+SETGID" in entry
    assert "entrypoint uid=" in entry
    assert "tmpfs must be mode 0777" in entry or "mode 0777 under cap_drop" in entry
    assert "CAP_CHOWN" in entry or "chown(" in entry
    # Non-root + exports:ro must not abort on modsec_audit touch.
    assert "modsec_audit.log" in entry
    assert "not writable" in entry
    sync = (root / "docker/nginx/sync-exports-to-confd.sh").read_text(encoding="utf-8")
    assert "nginx-portal-realms.conf" in sync
    assert "/etc/nginx/includes/nginx-portal-realms.conf" in sync
    vhost = (root / "docker/nginx/templates/vhost_sso_portal.conf.template").read_text(
        encoding="utf-8"
    )
    assert "include /etc/nginx/includes/nginx-portal-realms.conf;" in vhost
    assert "include /var/lib/sso-portal/exports/nginx-portal-realms.conf;" not in vhost
    # nginx 1.30+ log_format app vars without subdomain_proxy vhosts
    assert 'set $auth_app "";' in vhost
    assert 'set $auth_source "";' in vhost
    migrate = (root / "docker-compose.yml").read_text(encoding="utf-8")
    assert "chown -R 101:65532 /var/lib/sso-portal/nginx-logs" in migrate
    acme = (root / "docker/nginx/sync-acme-tls.sh").read_text(encoding="utf-8")
    assert "acme-challenge webroot not writable" in acme
    assert "_mirror_cert" in acme
    assert "_chmod_ssl_local_readable" in acme
    assert "ACME TLS mirrored=" in acme
    assert "LOCAL_SSL/$fqdn" in acme or 'LOCAL_SSL/$fqdn' in acme
    assert 'umask 022' in acme or "chmod 644 \"$DEFAULT_KEY\"" in acme or 'chmod 644 "$DEFAULT_KEY"' in acme
    reconcile = (root / "docker/acme/reconcile-certs.sh").read_text(encoding="utf-8")
    assert "_chmod_nginx_readable" in reconcile
    assert "chmod 644" in reconcile


def test_technical_template_has_runtime_panel():
    root = Path(__file__).resolve().parents[1]
    html = (root / "app/templates/admin/waf.html").read_text(encoding="utf-8")
    assert "Durcissement Runtime" in html
    assert "runtime_hardening" in html
    assert "no_new_privileges" in html
