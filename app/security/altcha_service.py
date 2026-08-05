"""Self-hosted ALTCHA proof-of-work captcha (no third-party service)."""

from __future__ import annotations

import hashlib
import hmac
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from altcha import create_challenge_v1, solve_challenge_v1, verify_solution_v1

from app.sso_settings import Settings

logger = logging.getLogger(__name__)

# Complexity: ~0.1–1s on a typical laptop; bots pay CPU per attempt.
_DEFAULT_MAX_NUMBER = 100_000
_CHALLENGE_TTL = timedelta(minutes=5)
_REPLAY_TTL_SEC = 10 * 60

_replay_lock = threading.Lock()
_replay_seen: dict[str, float] = {}


def altcha_hmac_key(settings: Settings) -> str:
    """Dedicated HMAC key, or a derived key from the portal internal token."""
    configured = (getattr(settings, "altcha_hmac_key", None) or "").strip()
    if configured:
        return configured
    base = (settings.vault_portal_internal_token or "dev-insecure").encode("utf-8")
    return hmac.new(base, b"altcha-hmac-v1", hashlib.sha256).hexdigest()


def altcha_max_number(settings: Settings) -> int:
    raw = int(getattr(settings, "altcha_max_number", _DEFAULT_MAX_NUMBER) or _DEFAULT_MAX_NUMBER)
    return max(10_000, min(raw, 2_000_000))


def create_altcha_challenge(settings: Settings) -> dict:
    """Return a widget-compatible challenge JSON object."""
    challenge = create_challenge_v1(
        algorithm="SHA-256",
        max_number=altcha_max_number(settings),
        hmac_key=altcha_hmac_key(settings),
        expires=datetime.now(timezone.utc) + _CHALLENGE_TTL,
    )
    # Widget 1.x expects lowercase ``maxnumber``.
    return {
        "algorithm": challenge.algorithm,
        "challenge": challenge.challenge,
        "maxnumber": challenge.max_number,
        "salt": challenge.salt,
        "signature": challenge.signature,
    }


def verify_altcha_payload(settings: Settings, payload: str) -> bool:
    """Cryptographically verify + enforce one-time use of the ALTCHA payload."""
    raw = (payload or "").strip()
    if not raw:
        return False
    ok, reason = verify_solution_v1(
        raw,
        altcha_hmac_key(settings),
        check_expires=True,
    )
    if not ok:
        logger.info("altcha verify failed reason=%s", reason)
        return False
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    now = time.time()
    with _replay_lock:
        _purge_replay(now)
        if digest in _replay_seen:
            logger.info("altcha replay rejected")
            return False
        _replay_seen[digest] = now
    return True


def solve_altcha_for_tests(challenge: dict) -> str:
    """Build a base64 payload for tests (server-side solve)."""
    import base64
    import json

    solution = solve_challenge_v1(
        challenge["challenge"],
        challenge["salt"],
        algorithm=challenge.get("algorithm") or "SHA-256",
        max_number=int(challenge.get("maxnumber") or _DEFAULT_MAX_NUMBER),
    )
    if solution is None:
        raise RuntimeError("Failed to solve ALTCHA challenge in tests")
    number = solution.number if hasattr(solution, "number") else solution
    payload = {
        "algorithm": challenge["algorithm"],
        "challenge": challenge["challenge"],
        "number": number,
        "salt": challenge["salt"],
        "signature": challenge["signature"],
    }
    return base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()


def clear_altcha_replay_for_tests() -> None:
    with _replay_lock:
        _replay_seen.clear()


def _purge_replay(now: float) -> None:
    expired = [k for k, ts in _replay_seen.items() if now - ts > _REPLAY_TTL_SEC]
    for k in expired:
        del _replay_seen[k]
