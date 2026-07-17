"""Application logging configuration — text or JSON, LOG_LEVEL from settings."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from app.sso_settings import Settings

_CONFIGURED = False


class RequestIdFilter(logging.Filter):
    """Inject request_id from contextvar into log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        from app.logging_middleware import get_request_id

        record.request_id = get_request_id() or "-"  # type: ignore[attr-defined]
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


def configure_logging(settings: Settings | None = None) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    if settings is None:
        from app.sso_settings import get_settings

        settings = get_settings()

    level_name = (settings.log_level or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)

    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RequestIdFilter())
    if (settings.log_format or "text").lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(TextFormatter())

    # Replace existing handlers to avoid duplicate lines in tests/reloads
    root.handlers.clear()
    root.addHandler(handler)
    _CONFIGURED = True


def reset_logging_config_for_tests() -> None:
    global _CONFIGURED
    _CONFIGURED = False
