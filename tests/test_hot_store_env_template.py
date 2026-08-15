"""The .env line that feeds both postgres and the app must survive every alias.

A missing ``HOT_STORE_PG_PASSWORD`` in .env is not a quiet degradation: compose
falls back to ``bastion_hot_change_me`` for the role while the app connects with
the value stored in portal_settings, and the hot store is locked out.
"""

from pathlib import Path

import yaml
from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "bastion_app_docker"
TEMPLATE = ROLE / "templates" / "portal.env.j2"
DEFAULTS = ROLE / "defaults" / "main.yml"

REQUIRED = {
    "portal_domain": "portal.example.test",
    "sso_portal_default_realm_slug": "portal",
    "vault_portal_internal_token": "token",
    "vault_sso_portal_oidc_client_secret": "secret",
    "vault_portal_vault_fernet_key": "fernet",
    "vault_portal_db_encryption_key": "0" * 64,
    "bastion_app_docker_data_dir": "/tools/portal/data",
    "bastion_app_docker_files_data_dir": "/tools/portal/data-files",
    "oauth2_proxy_image_tag": "latest",
    "ansible_managed": "managed",
}


def render_env(**overrides) -> str:
    """Render portal.env.j2 the way Ansible would, defaults included.

    Ansible templates variables lazily, so ``hot_store_pg_password_resolved`` is
    itself a Jinja expression that must be resolved before the file template.
    """
    env = Environment(keep_trailing_newline=True)
    variables = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))
    variables.update(REQUIRED)
    variables.update(overrides)
    resolved = variables.pop("hot_store_pg_password_resolved")
    variables["hot_store_pg_password_resolved"] = env.from_string(resolved).render(
        **variables
    )
    return env.from_string(TEMPLATE.read_text(encoding="utf-8")).render(**variables)


def test_no_password_omits_the_block():
    assert "HOT_STORE_PG_PASSWORD" not in render_env()


def test_vault_name_reaches_env():
    out = render_env(vault_hot_store_pg_password="s3cret-vault")
    assert "HOT_STORE_PG_PASSWORD=s3cret-vault" in out
    assert "HOT_STORE_PG_USER=bastion_hot" in out
    assert "HOT_STORE_PG_DB=bastion_hot" in out


def test_plain_alias_reaches_env():
    assert "HOT_STORE_PG_PASSWORD=s3cret-plain" in render_env(
        hot_store_pg_password="s3cret-plain"
    )


def test_uppercase_alias_reaches_env():
    """Documented alias: it used to be shadowed by the empty defaults above it."""
    assert "HOT_STORE_PG_PASSWORD=s3cret-upper" in render_env(
        HOT_STORE_PG_PASSWORD="s3cret-upper"
    )


def test_vault_name_wins_over_aliases():
    out = render_env(
        vault_hot_store_pg_password="from-vault",
        hot_store_pg_password="from-plain",
        HOT_STORE_PG_PASSWORD="from-upper",
    )
    assert "HOT_STORE_PG_PASSWORD=from-vault" in out


def test_surrounding_whitespace_is_dropped():
    """A trailing newline pasted into AWX would otherwise reach the role."""
    assert "HOT_STORE_PG_PASSWORD=s3cret\n" in render_env(
        vault_hot_store_pg_password="  s3cret\n"
    )


def test_preflight_guards_a_provisioned_hot_store():
    text = (ROLE / "tasks" / "preflight.yml").read_text(encoding="utf-8")
    assert "pgdata" in text
    assert "hot_store_pg_password_resolved" in text
