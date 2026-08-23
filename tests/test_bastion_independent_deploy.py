"""Structural checks for independent bastion deploy (edge + docker AWX entry)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_playbook_hosts_are_awx_driven():
    text = (ROOT / "ansible" / "linux_sso_portal_docker.yml").read_text(encoding="utf-8")
    assert "Refuse local/obsolete entry point" not in text
    assert "bastion_app_docker" in text
    assert "bastion_edge_dmz" in text
    assert "validate_purge" in text
    assert "bastion_docker_play_hosts" in text
    assert "bastion_edge_play_hosts" in text
    assert "default('all')" in text
    assert "Limit" in text or "inventaire AWX" in text
    assert "hosts: vmdmz-docker01" not in text
    assert "hosts: vmdmz-reverse01" not in text
    # Must not require AWX groups that may not exist
    assert "default('sso_portal_docker')" not in text
    assert "default('nginx_dmz" not in text


def test_edge_role_catchall_template():
    role = ROOT / "ansible" / "roles" / "bastion_edge_dmz"
    assert (role / "tasks" / "main.yml").is_file()
    assert (role / "tasks" / "smoke.yml").is_file()
    tpl = (role / "templates" / "vhost_bastion_edge_catchall.conf.j2").read_text(
        encoding="utf-8"
    )
    assert "X-Portal-Client-IP" in tpl
    assert "default_server" in tpl
    assert "bastion_upstream_url" in tpl
    assert "proxy_ssl_server_name on" in tpl


def test_infra_proxy_template_no_auth():
    tpl = (
        ROOT
        / "ansible"
        / "roles"
        / "bastion_app_docker"
        / "templates"
        / "nginx-infra-proxy-apps.conf.j2"
    ).read_text(encoding="utf-8")
    assert "auth_request" not in tpl
    assert "oauth2" not in tpl
    assert "listen 0.0.0.0:8080" in tpl
    assert "bastion_infra_proxy_vhosts" in tpl
    assert "X-Forwarded-Proto $bastion_forwarded_proto" in tpl
    assert "X-Forwarded-Port  $bastion_forwarded_port" in tpl


def test_nginx_http_forwarded_proto_map():
    conf = (ROOT / "docker" / "nginx" / "nginx.conf").read_text(encoding="utf-8")
    assert "map $http_x_forwarded_proto $bastion_forwarded_proto" in conf
    assert '""      https' in conf


def test_nginx_worker_fd_limits_above_default():
    """Avoid accept4 EMFILE / bare nginx 403 under portal+auth_request load."""
    conf = (ROOT / "docker" / "nginx" / "nginx.conf").read_text(encoding="utf-8")
    assert "worker_rlimit_nofile 65535;" in conf
    assert "worker_connections 8192;" in conf
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "ulimits:" in compose
    assert "nofile:" in compose
    assert "65535" in compose


def test_entrypoint_copies_infra_proxy_export():
    sync = (ROOT / "docker" / "nginx" / "sync-exports-to-confd.sh").read_text(
        encoding="utf-8"
    )
    assert "nginx-infra-proxy-apps.conf" in sync
    assert "nginx-public-proxy-apps.conf" in sync
    entry = (ROOT / "docker" / "nginx" / "docker-entrypoint.sh").read_text(
        encoding="utf-8"
    )
    assert "sync-exports-to-confd.sh" in entry


def test_entrypoint_registers_alpine_crontab_for_5min_waf_snapshot():
    """Alpine crond never runs /etc/periodic/5min unless crontab is patched."""
    entry = (ROOT / "docker" / "nginx" / "docker-entrypoint.sh").read_text(
        encoding="utf-8"
    )
    assert "/etc/periodic/5min/waf-snapshot" in entry
    assert "run-parts /etc/periodic/5min" in entry
    assert "*/5 * * * * run-parts /etc/periodic/5min" in entry


def test_traefik_catchall_example_present():
    path = ROOT / "docker" / "traefik" / "bastion-catchall.example.yml"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "bastion-nginx:8080" in text
    assert "bastion-catchall" in text


def test_inventory_example_has_edge_and_docker():
    inv = (
        ROOT / "ansible" / "inventory" / "inventory_sso_portal.ini.example"
    ).read_text(encoding="utf-8")
    assert "sso_portal_docker" in inv
    assert "sso_portal_edge" in inv
    assert "bastion_edge_catchall_enabled" in inv
