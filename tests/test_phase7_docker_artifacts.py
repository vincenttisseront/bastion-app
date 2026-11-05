"""Smoke structural checks for Phase 7 Docker artifacts (no Docker daemon required)."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = [ROOT / "Dockerfile", ROOT / "docker" / "nginx" / "Dockerfile"]

# Instructions whose arguments Docker takes literally (no shell): a trailing
# "# ..." is NOT a comment there, it becomes part of the value.
_LITERAL_INSTRUCTIONS = (
    "ADD|ARG|COPY|ENV|EXPOSE|FROM|LABEL|ONBUILD|SHELL|STOPSIGNAL|USER|VOLUME|WORKDIR"
)
_INLINE_COMMENT_RE = re.compile(rf"^\s*(?:{_LITERAL_INSTRUCTIONS})\s.*\s#", re.IGNORECASE)


def _instruction_starts(path: Path) -> list[str]:
    """Physical lines that start an instruction (continuation lines skipped)."""
    starts: list[str] = []
    continued = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if not continued and line.strip() and not line.lstrip().startswith("#"):
            starts.append(line)
        continued = line.rstrip().endswith("\\")
    return starts


def _user_values(path: Path) -> list[str]:
    return [
        ln.split(None, 1)[1].strip()
        for ln in _instruction_starts(path)
        if ln.strip().upper().startswith("USER ")
    ]


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_dockerfile_has_no_inline_comment_on_literal_instruction(dockerfile):
    """Regression: ``USER root  # NOSONAR ...`` set the image user to that whole string."""
    offenders = [ln.strip() for ln in _instruction_starts(dockerfile) if _INLINE_COMMENT_RE.match(ln)]
    assert not offenders, f"move these comments to their own line: {offenders}"


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_dockerfile_user_values_are_plain_identities(dockerfile):
    users = _user_values(dockerfile)
    assert users, f"{dockerfile} has no USER instruction"
    for user in users:
        assert re.fullmatch(r"[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)?", user), user


def test_dockerfile_no_alembic_in_runtime_cmd():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    # Multi-stage: migrate target has alembic; runtime CMD must not.
    runtime = text.split("AS runtime", 1)[1].split("AS migrate", 1)[0]
    assert "CMD" in runtime
    assert "alembic" not in runtime.split("CMD", 1)[-1]
    assert "HEALTHCHECK" in runtime
    assert "uvicorn" in runtime


def _compose_service_block(compose: Path, service: str) -> str:
    text = compose.read_text(encoding="utf-8")
    block = text.split(f"\n  {service}:\n", 1)[1]
    return re.split(r"\n  [A-Za-z0-9_-]+:\n", block, maxsplit=1)[0]


@pytest.mark.parametrize(
    "dockerfile, stage_marker, service",
    [
        (ROOT / "docker" / "nginx" / "Dockerfile", None, "nginx"),
        (ROOT / "Dockerfile", "AS migrate", "bastion-app-migrate"),
    ],
    ids=["nginx", "migrate"],
)
def test_image_defaults_to_nonroot_and_compose_elevates(tmp_path, dockerfile, stage_marker, service):
    """docker:S6471 — image default user is non-root; compose pins 0:0 where root is needed.

    nginx: the entrypoint mirrors root:600 ACME PEMs then su-execs to nginx.
    migrate: the one-shot job chowns data volumes.
    """
    text = dockerfile.read_text(encoding="utf-8")
    if stage_marker:
        text = text.split(stage_marker, 1)[1]
    stage = tmp_path / "Dockerfile.stage"
    stage.write_text(text, encoding="utf-8")
    users = _user_values(stage)
    assert users, f"{dockerfile} ({stage_marker or 'final'}) has no USER instruction"
    assert users[-1].split(":")[0] not in {"root", "0"}
    for compose in (ROOT / "docker-compose.yml", ROOT / "deploy" / "docker-compose.yml"):
        assert 'user: "0:0"' in _compose_service_block(compose, service), compose


def test_nginx_entrypoint_drops_root_to_nginx():
    entry = (ROOT / "docker" / "nginx" / "docker-entrypoint.sh").read_text(encoding="utf-8")
    assert "exec su-exec nginx:nginx" in entry


def test_compose_split_topology_binds():
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "127.0.0.1:8000:8000" in text
    assert "127.0.0.1:4180:4180" in text
    assert "vpcbr" in text
    assert "traefik.enable=true" not in text
    assert "container_name: bastion-nginx" in text
    assert '"80:80"' in text
    assert '"443:443"' in text
    assert "127.0.0.1:8080:8080" in text
    assert "bastion-app-migrate" in text
    # All services on vpcbr only (Keycloak pattern, 10.5.0.0/16)
    assert "bastion_net" not in text
    assert "10.5.0.0/16" in text
    assert "external: true" in text


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
    assert ".reconcile_request" in body
    assert "exec -T acme-companion" not in body


def test_apply_infra_docker_dispatch_script_exists():
    script = ROOT / "scripts" / "apply-infra-docker-dispatch.sh"
    assert script.is_file()
    body = script.read_text(encoding="utf-8")
    assert "apply-infra.request" in body
    assert "apply-infra.status" in body
    assert "apply-infra-docker.sh" in body
    role = ROOT / "ansible" / "roles" / "bastion_app_docker"
    assert (role / "templates" / "bastion-apply-infra.path.j2").is_file()
    assert (role / "templates" / "bastion-apply-infra.service.j2").is_file()
    main = (role / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "bastion-apply-infra.path" in main
    assert "apply-infra-docker-dispatch.sh" in main


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
        ROOT / "docker" / "nginx" / "templates" / "nginx-portal-core-realm-oauth2.conf.template"
    ).read_text(encoding="utf-8")
    assert "oauth2-proxy-core:4180" in core or "$oauth2_core_upstream" in core
    assert "${SSO_PORTAL_DEFAULT_REALM_SLUG}" in core
    assert "example-corp" not in core


def test_ansible_docker_role_present():
    role = ROOT / "ansible" / "roles" / "bastion_app_docker"
    assert (role / "tasks" / "preflight.yml").is_file()
    assert (role / "tasks" / "main.yml").is_file()
    assert (role / "tasks" / "smoke_test.yml").is_file()
    assert (ROOT / "ansible" / "linux_sso_portal_docker.yml").is_file()
    assert (ROOT / "ansible" / "roles" / "bastion_edge_dmz" / "tasks" / "main.yml").is_file()
