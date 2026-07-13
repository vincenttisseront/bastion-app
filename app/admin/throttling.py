"""In-memory rate limiting for realm OIDC tests."""

from __future__ import annotations

import time
from threading import Lock

_lock = Lock()
_last_test_at: dict[str, float] = {}
_COOLDOWN_SECONDS = 5.0


def check_test_rate_limit(key: str) -> float | None:
    """Return seconds to wait if throttled, else None."""
    now = time.monotonic()
    with _lock:
        last = _last_test_at.get(key)
        if last is not None and (now - last) < _COOLDOWN_SECONDS:
            return _COOLDOWN_SECONDS - (now - last)
        _last_test_at[key] = now
    return None


def reset_test_rate_limits() -> None:
    with _lock:
        _last_test_at.clear()
