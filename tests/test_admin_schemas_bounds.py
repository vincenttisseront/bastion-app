"""Pydantic max_length bounds for realm admin forms (ReDoS defence)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.admin.schemas import RealmConfigCreate


def _valid(**overrides):
    base = {
        "name": "Default",
        "slug": "default",
        "issuer_url": "https://idp.example.com/realms/default",
        "client_id": "portal",
        "client_secret": "secret",
        "oauth2_proxy_port": 4180,
    }
    base.update(overrides)
    return base


def test_slug_max_length_rejected():
    payload = _valid(slug="a" * 41)
    with pytest.raises(ValidationError) as exc:
        RealmConfigCreate(**payload)
    assert "slug" in str(exc.value).lower() or any(
        e["loc"] == ("slug",) for e in exc.value.errors()
    )


def test_slug_pattern_still_enforced():
    payload = _valid(slug="BAD_SLUG")
    with pytest.raises(ValidationError):
        RealmConfigCreate(**payload)


def test_issuer_url_max_length_rejected():
    payload = _valid(issuer_url="https://" + ("x" * 2041))
    with pytest.raises(ValidationError):
        RealmConfigCreate(**payload)


def test_optional_stripped_and_blank_secret_helpers():
    from app.admin.schemas import (
        RealmConfigUpdate,
        _optional_secret_blank_to_none,
        _optional_stripped,
    )

    assert _optional_stripped(None) is None
    assert _optional_stripped("  ") is None
    assert _optional_stripped("  abc  ") == "abc"
    assert _optional_secret_blank_to_none(None) is None
    assert _optional_secret_blank_to_none("  ") is None
    assert _optional_secret_blank_to_none("keep") == "keep"

    updated = RealmConfigUpdate(
        name="Default",
        issuer_url="https://idp.example.com/realms/default",
        client_id="portal",
        oauth2_proxy_port=4180,
        client_secret="   ",
        keycloak_admin_client_secret="   ",
    )
    assert updated.client_secret is None
    assert updated.keycloak_admin_client_secret is None
