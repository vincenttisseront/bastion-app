"""Shared password complexity rules for self-service profile password change."""

from __future__ import annotations

import re

MIN_PASSWORD_LEN = 12

_PUNCT_RE = re.compile(r"[^\w\s]", re.UNICODE)

PASSWORD_POLICY_RULES: tuple[dict[str, str], ...] = (
    {"id": "length", "label": f"Au moins {MIN_PASSWORD_LEN} caractères"},
    {"id": "uppercase", "label": "Contient des majuscules"},
    {"id": "lowercase", "label": "Contient des minuscules"},
    {"id": "digit", "label": "Contient des chiffres"},
    {"id": "punctuation", "label": "Contient un caractère spécial"},
)


def password_policy_checks(password: str) -> dict[str, bool]:
    text = password or ""
    return {
        "length": len(text) >= MIN_PASSWORD_LEN,
        "uppercase": any(c.isupper() for c in text),
        "lowercase": any(c.islower() for c in text),
        "digit": any(c.isdigit() for c in text),
        "punctuation": bool(_PUNCT_RE.search(text)),
    }


def password_policy_violations(password: str) -> list[str]:
    checks = password_policy_checks(password)
    return [
        rule["label"]
        for rule in PASSWORD_POLICY_RULES
        if not checks.get(rule["id"], False)
    ]


def validate_password_policy(password: str) -> None:
    violations = password_policy_violations(password)
    if violations:
        raise ValueError(
            "Mot de passe insuffisamment complexe : " + " · ".join(violations)
        )
