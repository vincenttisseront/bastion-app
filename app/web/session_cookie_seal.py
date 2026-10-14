"""Encrypt upstream app session cookies kept in ``ActiveSession.details``.

Live verification replays these cookies, so they are full session credentials:
they are stored sealed with the vault Fernet key, never as plain JSON.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import Any

from app.secret_crypto import decrypt_secret, encrypt_secret
from app.sso_settings import get_settings

logger = logging.getLogger(__name__)

SEALED_KEY = "session_cookies_sealed"
_LEGACY_KEY = "session_cookies"


def seal_session_cookies(cookies: Mapping[str, str] | None) -> str | None:
    """Ciphertext for ``cookies``, or None when empty or the vault key is missing."""
    if not cookies:
        return None
    try:
        return encrypt_secret(json.dumps(dict(cookies)), get_settings())
    except ValueError:
        logger.warning("Vault key unavailable: app session cookies not kept for verification")
        return None


def open_session_cookies(details: Mapping[str, Any] | None) -> dict[str, str]:
    """Cookies stored on a session row; ``{}`` when absent or undecryptable."""
    details = details or {}
    sealed = details.get(SEALED_KEY)
    if sealed:
        try:
            value = json.loads(decrypt_secret(str(sealed), get_settings()))
        except (ValueError, TypeError):
            return {}
        return value if isinstance(value, dict) else {}
    legacy = details.get(_LEGACY_KEY)
    return dict(legacy) if isinstance(legacy, dict) else {}


def has_session_cookies(details: Mapping[str, Any] | None) -> bool:
    details = details or {}
    return bool(details.get(SEALED_KEY) or details.get(_LEGACY_KEY))


def strip_session_cookies(details: dict[str, Any]) -> dict[str, Any]:
    """Copy of ``details`` without any stored cookie value."""
    return {k: v for k, v in details.items() if k not in (SEALED_KEY, _LEGACY_KEY)}
