"""Organization / company-group naming helpers (shared by account + Keycloak)."""

from __future__ import annotations

import re


def normalize_organization_name(raw: str | None) -> str:
    """Trim + collapse whitespace — display name used as Keycloak/RBAC group name."""
    return " ".join((raw or "").split()).strip()


def organization_match_key(raw: str | None) -> str:
    """Compare key ignoring spaces, underscores, hyphens, dots and case.

    ``SDIS 81``, ``SDIS81``, ``SDIS_81``, ``/SDIS-81`` → ``sdis81``.
    """
    text = (raw or "").strip()
    if "/" in text:
        text = text.rstrip("/").rsplit("/", 1)[-1]
    return re.sub(r"[^a-z0-9]+", "", text.lower())
