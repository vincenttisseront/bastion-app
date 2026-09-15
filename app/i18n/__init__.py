"""Application internationalization (FR default, EN supported).

Message IDs are the French source strings (gettext-style). English catalogs map
French → English. Missing keys fall back to the msgid itself.
"""

from __future__ import annotations

from app.i18n.catalog import catalog_for, t
from app.i18n.resolve import (
    LOCALE_COOKIE,
    SUPPORTED_LOCALES,
    DEFAULT_LOCALE,
    normalize_locale,
    resolve_locale,
    set_locale_cookie,
)

__all__ = [
    "DEFAULT_LOCALE",
    "LOCALE_COOKIE",
    "SUPPORTED_LOCALES",
    "catalog_for",
    "normalize_locale",
    "resolve_locale",
    "set_locale_cookie",
    "t",
]
