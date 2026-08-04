"""Reject banned IPs / usernames / enforce hammering on sensitive bastion paths."""

from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.database import SessionLocal
from app.request_client_ip import client_ip_from_request
from app.security.banning.engine import (
    begin_concurrent,
    check_request_allowed,
    end_concurrent,
    identity_username_from_headers,
    is_sensitive_path,
    rate_limit_retry_after,
)

logger = logging.getLogger(__name__)

_SKIP_PREFIXES = (
    "/static/",
    "/media/",
    "/api/health",
    "/health",
    "/ready",
)


class SecurityBanMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if any(path.startswith(p) for p in _SKIP_PREFIXES):
            return await call_next(request)
        if not is_sensitive_path(path):
            return await call_next(request)

        ip = client_ip_from_request(request)
        username = identity_username_from_headers(request.headers)
        db = SessionLocal()
        tracked = False
        try:
            allowed, reason, _ban = check_request_allowed(
                db,
                ip=ip,
                path=path,
                method=request.method,
                username=username or None,
            )
            if not allowed:
                if reason == "rate_limited":
                    # Throttle (429 + Retry-After) — softer than a ban.
                    retry = rate_limit_retry_after(db, path, request.method)
                    logger.warning(
                        "security.rate_limited ip=%s path=%s method=%s "
                        "retry_after=%ss username=%s",
                        ip or "-",
                        path,
                        request.method,
                        max(1, retry),
                        username or "-",
                    )
                    return JSONResponse(
                        {"detail": "Too many requests"},
                        status_code=429,
                        headers={"Retry-After": str(max(1, retry))},
                    )
                detail = (
                    "Too many concurrent connections"
                    if reason == "concurrent_limit"
                    else "Access temporarily blocked"
                )
                status = 429 if reason == "concurrent_limit" else 403
                logger.warning(
                    "security.request_denied reason=%s ip=%s path=%s method=%s "
                    "status=%s username=%s",
                    reason,
                    ip or "-",
                    path,
                    request.method,
                    status,
                    username or "-",
                )
                return JSONResponse({"detail": detail}, status_code=status)

            begin_concurrent(ip)
            tracked = True
        except Exception:
            logger.exception("security ban middleware pre-check failed")
            try:
                db.rollback()
            except Exception:
                pass
        finally:
            db.close()

        try:
            return await call_next(request)
        finally:
            if tracked:
                end_concurrent(ip)
