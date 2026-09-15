"""Attach ``request.state.locale`` on every request."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.i18n.resolve import resolve_locale_from_request


class LocaleMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request.state.locale = resolve_locale_from_request(request)
        return await call_next(request)


def get_request_locale(request: Request) -> str:
    locale = getattr(request.state, "locale", None)
    if isinstance(locale, str) and locale:
        return locale
    return resolve_locale_from_request(request)
