"""Keycloak Admin API path suffixes: realm root readable, everything else still strict."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.rbac import keycloak_admin as kc

REALM = SimpleNamespace(issuer_url="https://kc.example.test/realms/acme")

_UNSAFE = [
    "users",
    "//evil.example/x",
    "/users/../clients",
    "/users/..",
    "https://evil.example/x",
    "/users\\abc",
]


def test_realm_root_only_with_opt_in():
    assert kc._safe_admin_api_path("", allow_realm_root=True) == ""
    with pytest.raises(ValueError):
        kc._safe_admin_api_path("")


@pytest.mark.parametrize("path", [" ", "\t", None])
def test_realm_root_requires_exact_empty_string(path):
    with pytest.raises(ValueError):
        kc._safe_admin_api_path(path, allow_realm_root=True)


@pytest.mark.parametrize("allow_realm_root", [False, True])
@pytest.mark.parametrize("path", _UNSAFE)
def test_unsafe_paths_still_rejected(path, allow_realm_root):
    with pytest.raises(ValueError):
        kc._safe_admin_api_path(path, allow_realm_root=allow_realm_root)


def test_sub_path_unchanged():
    assert kc._safe_admin_api_path("/users/abc", allow_realm_root=True) == "/users/abc"


async def test_writes_cannot_target_realm_root():
    # Rejected before any HTTP call: no respx route needed.
    with pytest.raises(ValueError, match="invalid Keycloak admin API path"):
        await kc._admin_send(REALM, None, "PUT", "", json={}, token="caller")
