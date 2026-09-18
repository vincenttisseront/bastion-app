"""Locale resolution from cookie / Accept-Language / default."""

from __future__ import annotations

from typing import Iterable

from fastapi import Request, Response
from starlette.datastructures import Headers

DEFAULT_LOCALE = "fr"
SUPPORTED_LOCALES: tuple[str, ...] = ("fr", "en")
LOCALE_COOKIE = "portal_locale"
LOCALE_COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year


def normalize_locale(value: str | None) -> str | None:
    if not value:
        return None
    raw = value.strip().lower().replace("_", "-")
    if not raw:
        return None
    primary = raw.split("-", 1)[0]
    if primary in SUPPORTED_LOCALES:
        return primary
    if raw in SUPPORTED_LOCALES:
        return raw
    return None


def parse_accept_language(header: str | None, supported: Iterable[str] = SUPPORTED_LOCALES) -> str | None:
    """Pick the best supported locale from an Accept-Language header."""
    if not header:
        return None
    supported_set = {s.lower() for s in supported}
    candidates: list[tuple[float, str]] = []
    for part in header.split(","):
        token = part.strip()
        if not token:
            continue
        lang_part, _, rest = token.partition(";")
        q = 1.0
        if rest.strip().lower().startswith("q="):
            try:
                q = float(rest.strip()[2:].strip())
            except ValueError:
                q = 0.0
        norm = normalize_locale(lang_part)
        if norm and norm in supported_set:
            candidates.append((q, norm))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (-item[0], item[1]))
    return candidates[0][1]


def resolve_locale(
    *,
    cookie: str | None = None,
    accept_language: str | None = None,
    default: str = DEFAULT_LOCALE,
) -> str:
    for candidate in (normalize_locale(cookie), parse_accept_language(accept_language)):
        if candidate:
            return candidate
    return normalize_locale(default) or DEFAULT_LOCALE


def resolve_locale_from_request(request: Request) -> str:
    cookie = request.cookies.get(LOCALE_COOKIE)
    accept = request.headers.get("accept-language")
    return resolve_locale(cookie=cookie, accept_language=accept)


def locale_from_headers(headers: Headers) -> str:
    return resolve_locale(
        cookie=None,
        accept_language=headers.get("accept-language"),
    )


def set_locale_cookie(response: Response, locale: str, *, secure: bool = False) -> str:
    loc = normalize_locale(locale) or DEFAULT_LOCALE
    response.set_cookie(
        key=LOCALE_COOKIE,
        value=loc,
        max_age=LOCALE_COOKIE_MAX_AGE,
        # JS locale switcher reads document.cookie — HttpOnly would break the mirror.
        httponly=False,  # NOSONAR python:S3330
        samesite="lax",
        path="/",
        secure=secure,
    )
    return loc
