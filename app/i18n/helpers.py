"""Helpers to localize label dictionaries and request-scoped ``t``."""

from __future__ import annotations

from typing import Any, Mapping

from fastapi import Request

from app.i18n.catalog import catalog_for, t
from app.i18n.middleware import get_request_locale
from app.i18n.resolve import DEFAULT_LOCALE


def request_t(request: Request | None, msgid: str, **kwargs: Any) -> str:
    locale = get_request_locale(request) if request is not None else DEFAULT_LOCALE
    return t(msgid, locale, **kwargs)


def localize_mapping(mapping: Mapping[str, str], locale: str) -> dict[str, str]:
    """Translate dict values (French msgids) for the given locale."""
    if locale == DEFAULT_LOCALE:
        return dict(mapping)
    return {key: t(value, locale) for key, value in mapping.items()}


def jinja_translate(msgid: str, **kwargs: Any) -> str:
    """Jinja global — uses locale from the active template context via kwargs ``_locale``."""
    locale = kwargs.pop("_locale", None) or DEFAULT_LOCALE
    return t(str(msgid), locale, **kwargs)


def build_js_catalog(locale: str) -> dict[str, str]:
    """Catalog blob for ``window.__i18n`` (EN map or empty for FR)."""
    if locale == DEFAULT_LOCALE:
        return {}
    return dict(catalog_for(locale))
