"""Locale preference endpoint."""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse

from app.i18n.resolve import SUPPORTED_LOCALES, normalize_locale, set_locale_cookie
from app.sso_settings import get_settings

router = APIRouter(tags=["i18n"])


def _safe_next_url(raw: str | None, request: Request) -> str:
    candidate = (raw or "").strip() or request.headers.get("referer") or "/dashboard"
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        # Only same-host absolute URLs; otherwise fall back to path-only.
        if parsed.netloc and parsed.netloc != request.url.netloc:
            return "/dashboard"
        path = parsed.path or "/dashboard"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path
    if not candidate.startswith("/"):
        return "/dashboard"
    return candidate


@router.post("/api/locale")
async def set_locale_api(
    request: Request,
    locale: str = Form(...),
    next: str = Form(""),
):
    settings = get_settings()
    loc = normalize_locale(locale)
    if loc is None or loc not in SUPPORTED_LOCALES:
        return JSONResponse(
            {"code": "bad_request", "message": "Unsupported locale."},
            status_code=400,
        )
    wants_json = "application/json" in (request.headers.get("accept") or "").lower()
    if wants_json and not next:
        response: RedirectResponse | JSONResponse = JSONResponse(
            {"status": "ok", "locale": loc}
        )
    else:
        response = RedirectResponse(url=_safe_next_url(next, request), status_code=303)
    set_locale_cookie(response, loc, secure=bool(getattr(settings, "is_production", False)))
    return response


@router.get("/api/locale")
async def get_locale_api(request: Request):
    from app.i18n.middleware import get_request_locale

    return {"locale": get_request_locale(request), "supported": list(SUPPORTED_LOCALES)}
