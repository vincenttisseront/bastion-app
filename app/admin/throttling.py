"""In-memory rate limiting for realm OIDC / credential / health tests.

Delegates to ``app.testing_framework.throttle`` — kept for import compatibility.
"""

from __future__ import annotations

from app.testing_framework.throttle import (
    clear_failures,
    failure_block_retry_after,
    record_failure,
    reset_throttles,
    throttle_retry_after,
    throttle_retry_after_key,
)

_TEST_COOLDOWN_SECONDS = 5.0
_SYNC_COOLDOWN_SECONDS = 30.0

# Identity password attempts: 5 failures / 5 minutes
IDENTITY_MAX_FAILURES = 5
IDENTITY_FAILURE_WINDOW_SECONDS = 300.0


def check_test_rate_limit(key: str) -> float | None:
    """Return seconds to wait if throttled, else None. Key format: ``type:id``."""
    return throttle_retry_after_key(key, _TEST_COOLDOWN_SECONDS)


def check_sync_rate_limit(key: str) -> float | None:
    return throttle_retry_after_key(key, _SYNC_COOLDOWN_SECONDS)


def check_identity_attempt_block(slug: str, user_key: str) -> float | None:
    """Return seconds to wait if identity password attempts are blocked."""
    return failure_block_retry_after(
        "identite_utilisateur",
        f"{slug}:{user_key}",
        max_failures=IDENTITY_MAX_FAILURES,
        window_seconds=IDENTITY_FAILURE_WINDOW_SECONDS,
    )


def record_identity_failure(slug: str, user_key: str) -> None:
    record_failure(
        "identite_utilisateur",
        f"{slug}:{user_key}",
        window_seconds=IDENTITY_FAILURE_WINDOW_SECONDS,
    )


def clear_identity_failures(slug: str, user_key: str) -> None:
    clear_failures("identite_utilisateur", f"{slug}:{user_key}")


def reset_test_rate_limits() -> None:
    reset_throttles()
