"""Always-on IP throttles for public access-request endpoints."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

# POST /auth/access-request — stop spam even when admin rate-limit rules are off.
_POST_LIMIT = 8
_POST_WINDOW_SEC = 15 * 60

# GET /auth/altcha/challenge — avoid challenge farming / DoS.
_CHALLENGE_LIMIT = 30
_CHALLENGE_WINDOW_SEC = 60

_lock = threading.Lock()
_buckets: dict[str, deque[float]] = defaultdict(deque)


def check_access_request_post_rate(ip: str | None) -> float | None:
    """Return retry-after seconds if over the access-request POST budget."""
    return _check(ip, scope="access_request_post", limit=_POST_LIMIT, window=_POST_WINDOW_SEC)


def check_forgot_password_post_rate(ip: str | None) -> float | None:
    """Return retry-after seconds if over the forgot-password POST budget."""
    return _check(ip, scope="forgot_password_post", limit=5, window=_POST_WINDOW_SEC)


def check_altcha_challenge_rate(ip: str | None) -> float | None:
    """Return retry-after seconds if over the challenge GET budget."""
    return _check(ip, scope="altcha_challenge", limit=_CHALLENGE_LIMIT, window=_CHALLENGE_WINDOW_SEC)


def clear_access_request_throttle_for_tests() -> None:
    with _lock:
        _buckets.clear()


def _check(ip: str | None, *, scope: str, limit: int, window: float) -> float | None:
    key_ip = (ip or "").strip() or "unknown"
    key = f"{scope}:{key_ip}"
    now = time.monotonic()
    with _lock:
        q = _buckets[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            retry = window - (now - q[0])
            return max(1.0, retry)
        q.append(now)
    return None
