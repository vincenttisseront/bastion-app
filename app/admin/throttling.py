"""In-memory rate limiting for realm OIDC tests."""

from __future__ import annotations

import time
from threading import Lock

_lock = Lock()
_last_test_at: dict[str, float] = {}
_TEST_COOLDOWN_SECONDS = 5.0
_SYNC_COOLDOWN_SECONDS = 30.0


def _check_rate_limit(key: str, cooldown_seconds: float) -> float | None:
    """Return seconds to wait if throttled, else None."""
    now = time.monotonic()
    with _lock:
        last = _last_test_at.get(key)
        if last is not None and (now - last) < cooldown_seconds:
            return cooldown_seconds - (now - last)
        _last_test_at[key] = now
    return None


def check_test_rate_limit(key: str) -> float | None:
    return _check_rate_limit(key, _TEST_COOLDOWN_SECONDS)


def check_sync_rate_limit(key: str) -> float | None:
    return _check_rate_limit(key, _SYNC_COOLDOWN_SECONDS)


def reset_test_rate_limits() -> None:
    with _lock:
        _last_test_at.clear()
