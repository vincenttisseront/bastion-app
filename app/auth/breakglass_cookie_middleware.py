"""Rotate break-glass cookies on browser-visible FastAPI responses.

Nginx ``auth_request`` does not forward ``Set-Cookie`` from the auth
subresponse to the client. Rotating on ``/internal/oauth2-auth`` therefore
advances the DB tip while the browser keeps the old ``jti``, which looks like
replay after the grace window and cuts the chain (login redirect loops).

Validate-only on auth_request; rotate here after a successful portal response,
at most once per ``ROTATION_MIN_INTERVAL_SECONDS``.
"""

from __future__ import annotations

import base64
import json
import logging
import time

from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.auth.breakglass import (
    COOKIE_NAME,
    ROTATION_MIN_INTERVAL_SECONDS,
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


def _unverified_payload(raw: str) -> dict | None:
    """Decode the JWT middle segment without trusting it (rotation pre-filter only).

    Signature and claims are verified later by ``process_breakglass_auth_request``.
    """
    try:
        parts = raw.split(".")
        if len(parts) < 2:
            return None
        pad = "=" * (-len(parts[1]) % 4)
        value = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
    except (ValueError, json.JSONDecodeError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _rotation_due(raw: str) -> bool:
    """Cheap pre-filter on the unverified ``last`` claim; full checks run after.

    Only rotation supersedes a cookie and it requires a stale ``last``, so a
    superseded cookie inside its grace window is never skipped here.
    """
    claims = _unverified_payload(raw)
    if claims is None:
        return False
    try:
        last = int(claims.get("last") or claims.get("iat"))
    except (TypeError, ValueError):
        return True
    return time.time() - last >= ROTATION_MIN_INTERVAL_SECONDS


def _rotate(request: Request, response: Response, raw: str) -> None:
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
        logger.exception("breakglass cookie rotation failed path=%s", request.url.path)
    finally:
        db.close()


class BreakglassCookieRotationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        if response.status_code >= 400:
            return response
        if request.url.path.startswith(_SKIP_PREFIXES):
            return response
        raw = request.cookies.get(COOKIE_NAME)
        if not raw or not _rotation_due(raw):
            return response
        await run_in_threadpool(_rotate, request, response, raw)
        return response
