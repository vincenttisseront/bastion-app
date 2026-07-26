"""Reject banned IPs / enforce hammering on sensitive bastion paths."""

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
    is_sensitive_path,
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
        db = SessionLocal()
        tracked = False
        try:
            allowed, reason, _ban = check_request_allowed(
                db, ip=ip, path=path, method=request.method
            )
            if not allowed:
                detail = (
                    "Too many concurrent connections"
                    if reason == "concurrent_limit"
                    else "Access temporarily blocked"
                )
                status = 429 if reason == "concurrent_limit" else 403
                if path.startswith("/api/") or "application/json" in (
                    request.headers.get("accept") or ""
                ).lower():
                    return JSONResponse({"detail": detail}, status_code=status)
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
