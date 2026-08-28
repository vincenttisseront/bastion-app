"""Username derivation from prénom / nom."""

from __future__ import annotations

import pytest

from app.rbac.user_identity import (
    derive_username_from_names,
    format_identity_first_name,
    format_identity_last_name,
    parse_identity_from_username,
)


def test_derive_username_basic():
    assert derive_username_from_names("Laurent", "Vervier") == "laurent.vervier"


def test_derive_username_strips_accents():
    assert derive_username_from_names("François", "Müller") == "francois.muller"


def test_derive_username_hyphenated_first_name():
    assert derive_username_from_names("Jean-Pierre", "Dupont") == "jean-pierre.dupont"


def test_derive_username_requires_both_parts():
    with pytest.raises(ValueError, match="requis"):
        derive_username_from_names("Laurent", "")


def test_format_identity_names():
    assert format_identity_first_name("jean-pierre") == "Jean-Pierre"
    assert format_identity_last_name("vervier") == "VERVIER"


def test_parse_identity_from_username():
    assert parse_identity_from_username("laurent.vervier") == ("Laurent", "VERVIER")
    assert parse_identity_from_username("jean-pierre.dupont") == (
        "Jean-Pierre",
        "DUPONT",
    )
    assert parse_identity_from_username("alice") is None
