"""Strip secrets from anything sent to the LLM.

Runs on every prompt fragment before it leaves the process. Over-redaction is
the safe failure mode: a false positive costs a little context, a miss leaks
a credential into a model prompt (and into Ollama's own logs).

Patterns are RE2-compatible (``app.re_safe``): no lookaround, no backrefs.
"""

from __future__ import annotations

import json
from typing import Any

from app import re_safe

REDACTED = "[REDACTED]"

# Hard cap on what one prompt may carry (characters, after redaction).
MAX_PROMPT_CHARS = 24_000

_SECRET_KEY_FRAGMENT = (
    r"(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey|"
    r"authorization|cookie|session[_-]?id|sessionid|otp|totp|private[_-]?key|"
    r"credential|code[_-]?verifier|fernet|signature)"
)

_KEY_RE = re_safe.compile(rf"(?i)^[a-z0-9_.-]*{_SECRET_KEY_FRAGMENT}[a-z0-9_.-]*$")

# Ordered: structural blocks first, then token shapes, then key=value pairs.
_PATTERNS: tuple[tuple[Any, str], ...] = (
    (
        re_safe.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        REDACTED,
    ),
    # Cookie / Set-Cookie header lines (whole value).
    (re_safe.compile(r"(?im)\b(set-cookie|cookie)\s*:[^\r\n]*"), rf"\1: {REDACTED}"),
    # Authorization schemes.
    (
        re_safe.compile(r"(?i)\b(bearer|basic|digest|negotiate)\s+[A-Za-z0-9._~+/=-]{8,}"),
        rf"\1 {REDACTED}",
    ),
    # JWT / JWS.
    (
        re_safe.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"),
        REDACTED,
    ),
    # Fernet tokens (vault / secret_crypto ciphertexts).
    (re_safe.compile(r"\bgAAAAA[A-Za-z0-9_-]{20,}=*"), REDACTED),
    # Well-known provider key shapes.
    (re_safe.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re_safe.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), REDACTED),
    (re_safe.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), REDACTED),
    (re_safe.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), REDACTED),
    # user:password@ in URLs.
    (
        re_safe.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"),
        rf"\1{REDACTED}@",
    ),
    # key=value / key: value / "key": "value" (JSON, query strings, headers, logs).
    (
        re_safe.compile(
            rf"(?i)([\"']?[a-z0-9_.-]*{_SECRET_KEY_FRAGMENT}[a-z0-9_.-]*[\"']?\s*[:=]\s*)"
            r"(\"[^\"]*\"|'[^']*'|[^\s,;&}\]]+)"
        ),
        rf"\1{REDACTED}",
    ),
)


def redact_text(text: str | None) -> str:
    if not text:
        return ""
    out = str(text)
    for pattern, repl in _PATTERNS:
        out = pattern.sub(repl, out)
    return out


def redact(value: Any) -> Any:
    """Recursively redact a JSON-like structure (keys and string values)."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            skey = str(key)
            out[skey] = REDACTED if _KEY_RE.match(skey) else redact(item)
        return out
    if isinstance(value, (list, tuple, set)):
        return [redact(item) for item in value]
    return redact_text(str(value))


def to_prompt_data(value: Any, max_chars: int = MAX_PROMPT_CHARS) -> str:
    """Redact then serialise untrusted data for a prompt, capped in size."""
    if isinstance(value, str):
        text = redact_text(value)
    else:
        text = json.dumps(redact(value), ensure_ascii=False, default=str, indent=1)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n[TRUNCATED]"
    return text
