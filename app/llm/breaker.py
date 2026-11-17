"""Circuit breaker for the optional LLM backend.

closed    → calls allowed; ``failure_threshold`` consecutive failures open it.
open      → no call, no network, until ``cooldown_s`` has elapsed.
half-open → exactly one trial call (a light ``/api/tags`` probe); success
            closes the breaker, failure re-opens it for a new cooldown.

State is per process (each uvicorn worker has its own breaker): this only
bounds how often a worker retries a dead Ollama, it is not a cluster lock.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 3,
        cooldown_s: float = 300.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.failure_threshold = max(1, int(failure_threshold))
        self.cooldown_s = max(1.0, float(cooldown_s))
        self._clock = clock
        self._lock = threading.Lock()
        self._failures = 0
        self._opened_at: float | None = None
        self._trial_in_flight = False
        self.last_error: str | None = None

    @property
    def state(self) -> str:
        with self._lock:
            return self._state_locked()

    def _state_locked(self) -> str:
        if self._opened_at is None:
            return CLOSED
        if self._clock() - self._opened_at >= self.cooldown_s:
            return HALF_OPEN
        return OPEN

    def acquire(self) -> str | None:
        """Return the state the call runs under, or ``None`` if it must not run.

        In half-open state only the first caller gets the trial slot; the
        others are refused until it reports success or failure.
        """
        with self._lock:
            state = self._state_locked()
            if state == CLOSED:
                return CLOSED
            if state == HALF_OPEN and not self._trial_in_flight:
                self._trial_in_flight = True
                return HALF_OPEN
            return None

    def success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._trial_in_flight = False
            self.last_error = None

    def failure(self, error: str | None = None) -> None:
        with self._lock:
            self.last_error = error
            was_trial = self._trial_in_flight
            self._trial_in_flight = False
            self._failures += 1
            if was_trial or self._failures >= self.failure_threshold:
                self._opened_at = self._clock()

    def release(self) -> None:
        """Give back a half-open trial slot without a verdict (call skipped)."""
        with self._lock:
            self._trial_in_flight = False

    def reset(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._trial_in_flight = False
            self.last_error = None
