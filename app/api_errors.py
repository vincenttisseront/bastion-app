"""Unified JSON error responses for REST/API clients."""

from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse

# Default machine-readable codes per HTTP status (subset used by Bastion).
_STATUS_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    422: "validation_error",
    429: "too_many_requests",
    500: "internal_error",
    503: "service_unavailable",
}


def api_error_response(
    *,
    status_code: int,
    message: str,
    code: str | None = None,
    errors: dict[str, Any] | list[Any] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Return a consistent JSON body: code, message, optional errors."""
    body: dict[str, Any] = {
        "code": code or _STATUS_CODES.get(status_code, "error"),
        "message": message,
    }
    if errors is not None:
        body["errors"] = errors
    return JSONResponse(body, status_code=status_code, headers=headers)


def api_error_from_detail(
    *,
    status_code: int,
    detail: Any,
    code: str | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Map HTTPException.detail (str or validation list) to unified JSON."""
    if isinstance(detail, str):
        message = detail
        errors: dict[str, Any] | list[Any] | None = None
    elif isinstance(detail, list):
        message = "Données invalides."
        errors = detail
        code = code or "validation_error"
    elif isinstance(detail, dict):
        message = str(detail.get("message") or detail.get("_form") or "Erreur.")
        errors = detail
    else:
        message = str(detail)
        errors = None
    return api_error_response(
        status_code=status_code,
        code=code,
        message=message,
        errors=errors,
        headers=headers,
    )
