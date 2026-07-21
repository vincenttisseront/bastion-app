"""Request ID middleware — X-Request-Id correlation for app + nginx logs.

Never logs request bodies (including POST /api/apps/{slug}/open-with-identity
passwords). Keep it that way: do not add body/query dumping here.
"""

from __future__ import annotations

import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)

HEADER_NAME = "X-Request-Id"


def get_request_id() -> str | None:
    return _request_id_ctx.get()


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        incoming = request.headers.get(HEADER_NAME, "").strip()
        request_id = incoming or str(uuid.uuid4())
        token = _request_id_ctx.set(request_id)
        try:
            response = await call_next(request)
        finally:
            _request_id_ctx.reset(token)
        response.headers[HEADER_NAME] = request_id
        return response
