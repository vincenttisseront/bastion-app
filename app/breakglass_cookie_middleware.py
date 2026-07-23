"""Rotate break-glass cookies on browser-visible FastAPI responses.

Nginx ``auth_request`` does not forward ``Set-Cookie`` from the auth
subresponse to the client. Rotating on ``/internal/oauth2-auth`` therefore
advances the DB tip while the browser keeps the old ``jti``, which looks like
replay after the grace window and cuts the chain (login redirect loops).

Validate-only on auth_request; rotate here after a successful portal response.
"""

from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.breakglass import (
    COOKIE_NAME,
    process_breakglass_auth_request,
    set_breakglass_cookie,
)
from app.database import SessionLocal
from app.sso_settings import get_settings

logger = logging.getLogger(__name__)

_SKIP_PREFIXES = (
    "/internal/",
    "/static/",
    "/media/",
    "/health",
    "/ready",
)


class BreakglassCookieRotationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        path = request.url.path
        if any(path.startswith(p) for p in _SKIP_PREFIXES):
            return response
        if response.status_code >= 400:
            return response
        raw = request.cookies.get(COOKIE_NAME)
        if not raw:
            return response

        db = SessionLocal()
        try:
            settings = get_settings()
            result = process_breakglass_auth_request(
                db, request, raw, settings, rotate=True
            )
            db.commit()
            if result.ok and result.set_cookie:
                set_breakglass_cookie(response, result.set_cookie, settings)
        except Exception:
            db.rollback()
            logger.exception("breakglass cookie rotation failed path=%s", path)
        finally:
            db.close()
        return response
