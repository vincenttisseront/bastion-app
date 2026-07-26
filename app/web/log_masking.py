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

# Prefer these keys for the compact table label (order = priority).
_SUMMARY_KEYS = (
    "reason",
    "error",
    "family",
    "policy",
    "status",
    "mode",
    "type",
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


def summarize_details_for_table(details: Any) -> str:
    """One short human label for the DÉTAIL column (not raw JSON)."""
    if details is None:
        return ""
    if isinstance(details, dict):
        masked = mask_secrets(details)
        parts: list[str] = []
        for key in _SUMMARY_KEYS:
            if key not in masked or masked[key] is None:
                continue
            val = masked[key]
            if isinstance(val, (dict, list)):
                continue
            text = str(val).strip()
            if not text or text == "***":
                continue
            if len(text) > 28:
                text = text[:27] + "…"
            parts.append(text)
            if len(parts) >= 2:
                break
        n = len(masked)
        if parts:
            label = " · ".join(parts)
            if n > 2:
                label = f"{label} · {n} champs"
            return label
        if n == 0:
            return "vide"
        return f"{n} champ" if n == 1 else f"{n} champs"
    if isinstance(details, list):
        n = len(details)
        return f"{n} élément" if n == 1 else f"{n} éléments"
    text = mask_secrets_text(str(details)).strip()
    if not text:
        return ""
    if len(text) > 36:
        return text[:35] + "…"
    return text


def format_details_for_display(details: Any, *, max_len: int = 120) -> tuple[str, str]:
    """Return (table_summary, full_pretty) for UI.

    ``full_pretty`` is always the complete masked payload (pretty JSON for
    dict/list). The first element is a compact label via
    ``summarize_details_for_table`` — not a truncated JSON dump.
    ``max_len`` is kept for call-site compatibility and ignored for summaries.
    """
    del max_len  # display summary is keyword-based, not character truncation
    if details is None:
        return "", ""
    summary = summarize_details_for_table(details)
    if isinstance(details, (dict, list)):
        masked = mask_secrets(details)
        pretty = json.dumps(masked, ensure_ascii=False, indent=2)
        return summary, pretty
    text = mask_secrets_text(str(details))
    return summary, text
