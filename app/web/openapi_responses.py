"""Shared OpenAPI ``responses`` maps for FastAPI routes (Sonar S8415)."""

from __future__ import annotations

from typing import Any

RESP_400: dict[int | str, dict[str, Any]] = {400: {"description": "Bad request"}}
RESP_401: dict[int | str, dict[str, Any]] = {401: {"description": "Unauthorized"}}
RESP_403: dict[int | str, dict[str, Any]] = {403: {"description": "Forbidden"}}
RESP_404: dict[int | str, dict[str, Any]] = {404: {"description": "Not found"}}
RESP_409: dict[int | str, dict[str, Any]] = {409: {"description": "Conflict"}}
RESP_422: dict[int | str, dict[str, Any]] = {422: {"description": "Validation error"}}
RESP_500: dict[int | str, dict[str, Any]] = {500: {"description": "Server error"}}
RESP_503: dict[int | str, dict[str, Any]] = {503: {"description": "Service unavailable"}}
