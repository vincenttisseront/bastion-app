"""Smoke structural checks for Phase 7 Docker artifacts (no Docker daemon required)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_no_alembic_in_cmd():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "alembic" not in text.split("CMD")[-1]
    assert "HEALTHCHECK" in text
    assert "uvicorn" in text


def test_compose_split_topology_binds():
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "127.0.0.1:8000:8000" in text
    assert "127.0.0.1:4180:4180" in text
    assert "vpcbr" in text
    assert "traefik.enable=true" in text
    assert "bastion-portal" in text
    assert "tls.certresolver=cloudflare" in text
    assert "container_name: bastion-nginx" in text
    assert '"80:80"' not in text
    assert '"443:443"' not in text
    assert "8080:8080" not in text  # prod: via Traefik, not host publish
    assert "bastion-app-migrate" in text
    # All services on vpcbr only (Keycloak pattern, 10.5.0.0/16)
    assert "bastion_net" not in text
    assert "10.5.0.0/16" in text
    assert "external: true" in text
    assert "bastion-portal-http" not in text


def test_compose_publish_override_for_local_smoke():
    text = (ROOT / "docker-compose.publish.yml").read_text(encoding="utf-8")
    assert "127.0.0.1:8080:8080" in text


def test_playbook_targets_docker_host():
    text = (ROOT / "ansible" / "linux_sso_portal_docker.yml").read_text(encoding="utf-8")
    assert "sso_portal_docker" in text
    assert "bastion_app_docker" in text
    # Independent entry: docker + edge hosts (not stub fail)
    assert "bastion_edge_dmz" in text
    assert "Refuse local/obsolete" not in text


def test_apply_infra_docker_script_exists():
    script = ROOT / "scripts" / "apply-infra-docker.sh"
    assert script.is_file()
    body = script.read_text(encoding="utf-8")
    assert "docker-compose.override.yml" in body
    assert "--remove-orphans" in body
    assert "purge-units.list" in body
    assert "oauth2-proxy-portal-" in body
    assert "nginx-infra-proxy-apps.conf" in body


def test_validate_purge_units_task_present():
    role = ROOT / "ansible" / "roles" / "bastion_app_docker"
    assert (role / "tasks" / "validate_purge_units.yml").is_file()
    playbook = (ROOT / "ansible" / "linux_sso_portal_docker.yml").read_text(encoding="utf-8")
    assert "validate_purge" in playbook
    assert "validate_purge_units.yml" in playbook


def test_nginx_docker_uses_service_dns():
    vhost = (
        ROOT / "docker" / "nginx" / "templates" / "vhost_sso_portal.conf.template"
    ).read_text(encoding="utf-8")
    assert "bastion-app:8000" in vhost or "$bastion_app_upstream" in vhost
    assert "listen 0.0.0.0:8080 default_server" in vhost
    assert "absolute_redirect off" in vhost
    assert "port_in_redirect off" in vhost
    assert "letsencrypt" not in vhost
    core = (
        ROOT / "docker" / "nginx" / "snippets" / "nginx-portal-core-realm-oauth2.conf"
    ).read_text(encoding="utf-8")
    assert "oauth2-proxy-core:4180" in core or "$oauth2_core_upstream" in core


def test_ansible_docker_role_present():
    role = ROOT / "ansible" / "roles" / "bastion_app_docker"
    assert (role / "tasks" / "preflight.yml").is_file()
    assert (role / "tasks" / "main.yml").is_file()
    assert (role / "tasks" / "smoke_test.yml").is_file()
    assert (ROOT / "ansible" / "linux_sso_portal_docker.yml").is_file()
    assert (ROOT / "ansible" / "roles" / "bastion_edge_dmz" / "tasks" / "main.yml").is_file()
