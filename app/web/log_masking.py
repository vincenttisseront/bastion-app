"""Audit log masking — defence in depth against secrets in detail payloads."""

from __future__ import annotations

import json
import re
from typing import Any

_SENSITIVE_PATTERNS = re.compile(
    r"(?i)(client_secret|password|passwd|token|api[_-]?key|authorization|bearer)\s*[:=]\s*['\"]?[^\s'\",}]+",
)

_SENSITIVE_KEYS = re.compile(
    r"(?i)^(client_secret|password|passwd|token|access_token|refresh_token|api_key|secret)$"
)


def mask_secrets(value: Any) -> Any:
    """Recursively mask sensitive keys/values in structures destined for display."""
    if value is None:
        return None
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if _SENSITIVE_KEYS.match(str(key)):
                out[key] = "***"
            else:
                out[key] = mask_secrets(item)
        return out
    if isinstance(value, list):
        return [mask_secrets(item) for item in value]
    if isinstance(value, str):
        return _SENSITIVE_PATTERNS.sub(r"\1=***", value)
    return value


def mask_secrets_text(text: str | None) -> str:
    if not text:
        return ""
    return _SENSITIVE_PATTERNS.sub(r"\1=***", text)


def format_details_for_display(details: Any, *, max_len: int = 120) -> tuple[str, str]:
    """Return (truncated_preview, full_for_expand) strings for UI.

    Truncation is display-only: ``full_for_expand`` is always the complete
    masked payload (pretty-printed JSON when the source is a dict/list).
    """
    if details is None:
        return "", ""
    if isinstance(details, (dict, list)):
        masked = mask_secrets(details)
        compact = json.dumps(masked, ensure_ascii=False)
        pretty = json.dumps(masked, ensure_ascii=False, indent=2)
    else:
        compact = mask_secrets_text(str(details))
        pretty = compact
    if len(compact) <= max_len:
        return compact, compact
    return compact[: max_len - 1] + "…", pretty
