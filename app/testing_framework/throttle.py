"""In-memory rate limiting for connection tests (no Redis)."""

from __future__ import annotations

import time
from threading import Lock

_lock = Lock()
_last_test_at: dict[str, float] = {}


def _key(resource_type: str, resource_id: str | int) -> str:
    return f"{resource_type}:{resource_id}"


def check_throttle(
    resource_type: str,
    resource_id: str | int,
    min_interval_seconds: int = 5,
) -> bool:
    """Return True if the test is allowed (and record timestamp), False if throttled."""
    return throttle_retry_after(resource_type, resource_id, min_interval_seconds) is None


def throttle_retry_after(
    resource_type: str,
    resource_id: str | int,
    min_interval_seconds: float = 5,
) -> float | None:
    """If throttled, return seconds to wait; else record attempt and return None."""
    key = _key(resource_type, resource_id)
    now = time.monotonic()
    cooldown = float(min_interval_seconds)
    with _lock:
        last = _last_test_at.get(key)
        if last is not None and (now - last) < cooldown:
            return cooldown - (now - last)
        _last_test_at[key] = now
    return None


def throttle_retry_after_key(key: str, min_interval_seconds: float = 5) -> float | None:
    """Legacy helper when the caller already built ``type:id`` as a single key."""
    now = time.monotonic()
    cooldown = float(min_interval_seconds)
    with _lock:
        last = _last_test_at.get(key)
        if last is not None and (now - last) < cooldown:
            return cooldown - (now - last)
        _last_test_at[key] = now
    return None


def reset_throttles() -> None:
    with _lock:
        _last_test_at.clear()
