"""ReDoS-safe regex facade backed by google-re2 (linear-time matching).

Prefer this module over the stdlib ``re`` for any pattern evaluated on
untrusted or unbounded input (HTTP bodies, access logs, cookies, admin forms).

google-re2 does not support lookaround or backreferences. Patterns that need
those features must not live here — rewrite them, or isolate stdlib ``re`` in
``asyncio.to_thread`` with a hard input length cap.

RE2 also caps counted repetitions at 1000 (``{0,1001}`` fails). Prefer
unbounded classes when the engine is RE2 (already linear-time), or truncate
input before matching.

If google-re2 is unavailable (rare packaging gap), we fall back to stdlib
``re`` and clamp input length to limit catastrophic backtracking impact.
"""

from __future__ import annotations

import logging
import re as _stdlib_re
from typing import Any

logger = logging.getLogger(__name__)

try:
    import re2 as _re2

    _USING_RE2 = True
except ImportError:  # pragma: no cover - CI/Linux always has the wheel
    _re2 = None  # type: ignore[assignment]
    _USING_RE2 = False
    logger.warning(
        "google-re2 unavailable — falling back to stdlib re with input length caps"
    )

# Soft caps applied only on the stdlib fallback path (RE2 is already linear).
DEFAULT_MAX_INPUT_LEN = 256 * 1024
VALIDATOR_MAX_INPUT_LEN = 4_096

# Re-export flag constants so callers can write ``re_safe.IGNORECASE``.
IGNORECASE = _stdlib_re.IGNORECASE
I = IGNORECASE
MULTILINE = _stdlib_re.MULTILINE
M = MULTILINE
DOTALL = _stdlib_re.DOTALL
S = DOTALL
VERBOSE = _stdlib_re.VERBOSE
X = VERBOSE
ASCII = _stdlib_re.ASCII
A = ASCII
UNICODE = _stdlib_re.UNICODE
U = UNICODE

error = _re2.error if _USING_RE2 else _stdlib_re.error  # type: ignore[union-attr]
escape = _re2.escape if _USING_RE2 else _stdlib_re.escape  # type: ignore[union-attr]


def using_re2() -> bool:
    """True when matching is backed by google-re2."""
    return _USING_RE2


def _options_from_flags(flags: int = 0) -> Any:
    """Map stdlib ``re`` flags to ``re2.Options`` (or pass flags through on fallback)."""
    if not _USING_RE2:
        return flags
    assert _re2 is not None
    if flags & VERBOSE:
        raise ValueError(
            "re_safe: VERBOSE/X is not supported with google-re2 — expand the pattern"
        )
    opts = _re2.Options()
    if flags & IGNORECASE:
        opts.case_sensitive = False
    if flags & DOTALL:
        opts.dot_nl = True
    if flags & MULTILINE:
        # RE2 default one_line=False already allows ^/$ near newlines.
        opts.one_line = False
    return opts


def _clamp(text: Any, max_input_len: int | None) -> Any:
    if text is None or max_input_len is None or _USING_RE2:
        return text
    if isinstance(text, (str, bytes)) and len(text) > max_input_len:
        return text[:max_input_len]
    return text


def compile(pattern: str | bytes, flags: int = 0) -> Any:
    """Compile ``pattern``. Raises on unsupported RE2 features."""
    if _USING_RE2:
        assert _re2 is not None
        return _re2.compile(pattern, _options_from_flags(flags))
    return _stdlib_re.compile(pattern, flags)


def search(
    pattern: Any,
    string: Any,
    flags: int = 0,
    *,
    max_input_len: int | None = DEFAULT_MAX_INPUT_LEN,
) -> Any:
    string = _clamp(string, max_input_len)
    if _USING_RE2:
        assert _re2 is not None
        if isinstance(pattern, str):
            return _re2.search(pattern, string, _options_from_flags(flags))
        return pattern.search(string)
    if isinstance(pattern, str):
        return _stdlib_re.search(pattern, string, flags)
    return pattern.search(string)


def match(
    pattern: Any,
    string: Any,
    flags: int = 0,
    *,
    max_input_len: int | None = DEFAULT_MAX_INPUT_LEN,
) -> Any:
    string = _clamp(string, max_input_len)
    if _USING_RE2:
        assert _re2 is not None
        if isinstance(pattern, str):
            return _re2.match(pattern, string, _options_from_flags(flags))
        return pattern.match(string)
    if isinstance(pattern, str):
        return _stdlib_re.match(pattern, string, flags)
    return pattern.match(string)


def fullmatch(
    pattern: Any,
    string: Any,
    flags: int = 0,
    *,
    max_input_len: int | None = VALIDATOR_MAX_INPUT_LEN,
) -> Any:
    string = _clamp(string, max_input_len)
    if _USING_RE2:
        assert _re2 is not None
        if isinstance(pattern, str):
            return _re2.fullmatch(pattern, string, _options_from_flags(flags))
        return pattern.fullmatch(string)
    if isinstance(pattern, str):
        return _stdlib_re.fullmatch(pattern, string, flags)
    return pattern.fullmatch(string)


def findall(
    pattern: Any,
    string: Any,
    flags: int = 0,
    *,
    max_input_len: int | None = DEFAULT_MAX_INPUT_LEN,
) -> list[Any]:
    string = _clamp(string, max_input_len)
    if _USING_RE2:
        assert _re2 is not None
        if isinstance(pattern, str):
            return list(_re2.findall(pattern, string, _options_from_flags(flags)))
        return list(pattern.findall(string))
    if isinstance(pattern, str):
        return _stdlib_re.findall(pattern, string, flags)
    return pattern.findall(string)


def finditer(
    pattern: Any,
    string: Any,
    flags: int = 0,
    *,
    max_input_len: int | None = DEFAULT_MAX_INPUT_LEN,
) -> Any:
    string = _clamp(string, max_input_len)
    if _USING_RE2:
        assert _re2 is not None
        if isinstance(pattern, str):
            return _re2.finditer(pattern, string, _options_from_flags(flags))
        return pattern.finditer(string)
    if isinstance(pattern, str):
        return _stdlib_re.finditer(pattern, string, flags)
    return pattern.finditer(string)


def sub(
    pattern: Any,
    repl: Any,
    string: Any,
    count: int = 0,
    flags: int = 0,
    *,
    max_input_len: int | None = DEFAULT_MAX_INPUT_LEN,
) -> Any:
    string = _clamp(string, max_input_len)
    if _USING_RE2:
        assert _re2 is not None
        if isinstance(pattern, str):
            return _re2.sub(pattern, repl, string, count=count, options=_options_from_flags(flags))
        return pattern.sub(repl, string, count=count)
    if isinstance(pattern, str):
        return _stdlib_re.sub(pattern, repl, string, count=count, flags=flags)
    return pattern.sub(repl, string, count=count)


def split(
    pattern: Any,
    string: Any,
    maxsplit: int = 0,
    flags: int = 0,
    *,
    max_input_len: int | None = DEFAULT_MAX_INPUT_LEN,
) -> list[Any]:
    string = _clamp(string, max_input_len)
    if _USING_RE2:
        assert _re2 is not None
        if isinstance(pattern, str):
            return list(
                _re2.split(
                    pattern,
                    string,
                    maxsplit=maxsplit,
                    options=_options_from_flags(flags),
                )
            )
        return list(pattern.split(string, maxsplit=maxsplit))
    if isinstance(pattern, str):
        return _stdlib_re.split(pattern, string, maxsplit=maxsplit, flags=flags)
    return pattern.split(string, maxsplit=maxsplit)
