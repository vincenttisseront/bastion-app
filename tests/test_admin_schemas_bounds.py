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
    with pytest.raises(ValidationError) as exc:
        RealmConfigCreate(**_valid(slug="a" * 41))
    assert "slug" in str(exc.value).lower() or any(
        e["loc"] == ("slug",) for e in exc.value.errors()
    )


def test_slug_pattern_still_enforced():
    with pytest.raises(ValidationError):
        RealmConfigCreate(**_valid(slug="BAD_SLUG"))


def test_issuer_url_max_length_rejected():
    with pytest.raises(ValidationError):
        RealmConfigCreate(**_valid(issuer_url="https://" + ("x" * 2041)))
