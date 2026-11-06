"""The playbook must pin the nginx memory cap in .env.

nginx keeps one parsed OWASP CRS per WAF vhost (~830 MB resident) and every
``nginx -t`` / reload loads one more copy: the compose default (2g) gets the
container OOM-killed when two reloads come close, so the role sets
``BASTION_NGINX_MEM_LIMIT`` and preflight rejects values compose would not take.
"""

import re
from pathlib import Path

import pytest
import yaml

from tests.test_hot_store_env_template import DEFAULTS, ROLE, render_env

PREFLIGHT = ROLE / "tasks" / "preflight.yml"
COMPOSE = Path(__file__).resolve().parents[1] / "deploy" / "docker-compose.yml"


def _env_lines(out: str) -> list[str]:
    return [ln for ln in out.splitlines() if ln.startswith("BASTION_NGINX_MEM_LIMIT=")]


def test_default_pins_4g():
    assert yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))["bastion_nginx_mem_limit"] == "4g"
    assert _env_lines(render_env()) == ["BASTION_NGINX_MEM_LIMIT=4g"]


def test_override_reaches_env():
    assert _env_lines(render_env(bastion_nginx_mem_limit=" 6g ")) == ["BASTION_NGINX_MEM_LIMIT=6g"]


@pytest.mark.parametrize("value", ["", "  "])
def test_empty_keeps_compose_default(value):
    assert _env_lines(render_env(bastion_nginx_mem_limit=value)) == []


def test_compose_reads_the_variable():
    nginx = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["nginx"]
    assert nginx["mem_limit"].startswith("${BASTION_NGINX_MEM_LIMIT:-")


def _preflight_pattern() -> str:
    tasks = yaml.safe_load(PREFLIGHT.read_text(encoding="utf-8"))
    task = next(t for t in tasks if t.get("name") == "PREFLIGHT : limite mémoire nginx")
    (cond,) = task["ansible.builtin.assert"]["that"]
    return re.search(r"is match\('([^']+)'\)", cond).group(1)


@pytest.mark.parametrize("value", ["4g", "4G", "4096m", "3500M", "2097152k"])
def test_preflight_accepts_docker_sizes(value):
    assert re.match(_preflight_pattern(), value)


@pytest.mark.parametrize("value", ["4", "4 g", "4gb", "4GiB", "-1g", "4.5g", "g", "4g\nX=1"])
def test_preflight_rejects_other_values(value):
    assert not re.match(_preflight_pattern(), value)
