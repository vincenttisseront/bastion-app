"""Password complexity policy for profile self-service."""

from __future__ import annotations

import pytest

from app.web.password_policy import (
    password_policy_checks,
    password_policy_violations,
    validate_password_policy,
)


def test_password_policy_accepts_strong_password():
    validate_password_policy("Correct-Horse-Battery99!")


def test_password_policy_rejects_weak_password():
    with pytest.raises(ValueError, match="complexe"):
        validate_password_policy("short")


def test_password_policy_checks_all_rules():
    checks = password_policy_checks("Aa1!aaaaaaaa")
    assert all(checks.values())


def test_password_policy_violations_lists_missing_rules():
    violations = password_policy_violations("alllowercase")
    assert any("majuscule" in v for v in violations)
    assert any("chiffre" in v for v in violations)
