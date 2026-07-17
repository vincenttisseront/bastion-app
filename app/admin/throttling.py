"""In-memory rate limiting for realm OIDC / credential / health tests.

Delegates to ``app.testing_framework.throttle`` — kept for import compatibility.
"""

from __future__ import annotations

from app.testing_framework.throttle import (
    reset_throttles,
    throttle_retry_after,
    throttle_retry_after_key,
)

_TEST_COOLDOWN_SECONDS = 5.0
_SYNC_COOLDOWN_SECONDS = 30.0


def check_test_rate_limit(key: str) -> float | None:
    """Return seconds to wait if throttled, else None. Key format: ``type:id``."""
    return throttle_retry_after_key(key, _TEST_COOLDOWN_SECONDS)


def check_sync_rate_limit(key: str) -> float | None:
    return throttle_retry_after_key(key, _SYNC_COOLDOWN_SECONDS)


def reset_test_rate_limits() -> None:
    reset_throttles()
