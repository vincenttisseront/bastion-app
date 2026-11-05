"""Reject banned IPs / usernames / enforce hammering on sensitive bastion paths."""

from __future__ import annotations

import logging

from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.api_errors import api_error_response
from app.database import SessionLocal
from app.request_client_ip import client_ip_from_request
from app.security.banning.engine import (
    begin_concurrent,
    check_request_allowed,
    end_concurrent,
    identity_username_from_headers,
    is_login_path,
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


def _security_denied_response(
    db,
    *,
    reason: str | None,
    ip: str | None,
    path: str,
    method: str,
    username: str | None,
) -> Response:
    if reason == "rate_limited":
        # Throttle (429 + Retry-After) — softer than a ban.
        retry = rate_limit_retry_after(db, path, method)
        logger.warning(
            "security.rate_limited ip=%s path=%s method=%s "
            "retry_after=%ss username=%s",
            ip or "-",
            path,
            method,
            max(1, retry),
            username or "-",
        )
        return api_error_response(
            status_code=429,
            message="Trop de requêtes — réessayez dans quelques instants.",
            headers={"Retry-After": str(max(1, retry))},
        )
    message = (
        "Trop de connexions simultanées."
        if reason == "concurrent_limit"
        else "Accès temporairement bloqué."
    )
    status = 429 if reason == "concurrent_limit" else 403
    logger.warning(
        "security.request_denied reason=%s ip=%s path=%s method=%s "
        "status=%s username=%s",
        reason,
        ip or "-",
        path,
        method,
        status,
        username or "-",
    )
    return api_error_response(status_code=status, message=message)


_PRECHECK_FAILED_MESSAGE = "Service temporairement indisponible."


def _pre_check(*, ip: str, path: str, method: str, username: str) -> Response | bool:
    """Ban / rate decision. Returns a deny response, or whether ``ip`` is tracked.

    S6: fail **closed** on login endpoints — if the check itself fails (e.g.
    database locked), brute-force protection must not silently switch off.
    Other sensitive paths stay fail-open (availability of authenticated pages).
    """
    db = SessionLocal()
    try:
        allowed, reason, _ban = check_request_allowed(
            db,
            ip=ip,
            path=path,
            method=method,
            username=username or None,
        )
        if not allowed:
            return _security_denied_response(
                db, reason=reason, ip=ip, path=path, method=method, username=username
            )
        begin_concurrent(ip)
        return True
    except Exception:
        logger.exception("security ban middleware pre-check failed")
        try:
            db.rollback()
        except Exception:
            pass
        if is_login_path(path, method):
            return api_error_response(
                status_code=503,
                message=_PRECHECK_FAILED_MESSAGE,
                headers={"Retry-After": "5"},
            )
        return False
    finally:
        db.close()


class SecurityBanMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if any(path.startswith(p) for p in _SKIP_PREFIXES):
            return await call_next(request)
        if not is_sensitive_path(path):
            return await call_next(request)

        ip = client_ip_from_request(request)
        username = identity_username_from_headers(request.headers)
        method = request.method
        # A1/S6: the ban check is synchronous SQL — run it in the threadpool so
        # a locked database cannot freeze the single worker's event loop.
        outcome = await run_in_threadpool(
            _pre_check, ip=ip, path=path, method=method, username=username
        )
        if isinstance(outcome, Response):
            return outcome
        tracked = outcome

        try:
            return await call_next(request)
        finally:
            if tracked:
                end_concurrent(ip)
