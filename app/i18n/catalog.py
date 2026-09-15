"""JSON message catalogs — French msgids, English translations."""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.i18n.resolve import DEFAULT_LOCALE, normalize_locale

logger = logging.getLogger("app.i18n")

_LOCALES_DIR = Path(__file__).resolve().parent / "locales"


@lru_cache(maxsize=8)
def _load_catalog(locale: str) -> dict[str, str]:
    path = _LOCALES_DIR / f"{locale}.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.exception("failed to load locale catalog %s", path)
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in data.items():
        if isinstance(key, str) and isinstance(value, str):
            out[key] = value
    return out


def catalog_for(locale: str | None = None) -> dict[str, str]:
    """Return the flat string catalog for *locale* (may be empty for ``fr``)."""
    loc = normalize_locale(locale) or DEFAULT_LOCALE
    return _load_catalog(loc)


def t(msgid: str, locale: str | None = None, **kwargs: Any) -> str:
    """Translate *msgid* (French source) into *locale*.

    Interpolation uses ``str.format`` with ``**kwargs`` when provided.
    """
    if not msgid:
        return ""
    loc = normalize_locale(locale) or DEFAULT_LOCALE
    if loc == DEFAULT_LOCALE:
        text = msgid
    else:
        text = _load_catalog(loc).get(msgid) or _load_catalog(DEFAULT_LOCALE).get(msgid) or msgid
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, ValueError, IndexError):
            return text
    return text


def clear_catalog_cache() -> None:
    """Test helper — drop cached JSON catalogs."""
    _load_catalog.cache_clear()
