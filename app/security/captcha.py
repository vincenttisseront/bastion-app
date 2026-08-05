"""Self-hosted math captcha for public forms (no third-party service)."""

from __future__ import annotations

import hmac
import secrets
import time
from dataclasses import dataclass
from hashlib import sha256

_CAPTCHA_TTL_SEC = 30 * 60
_MAX_OPERAND = 12


@dataclass(frozen=True)
class CaptchaChallenge:
    """Public challenge fields for the form (answer never included)."""

    question: str
    token: str


def issue_math_captcha(secret: str) -> CaptchaChallenge:
    """Create a short addition challenge signed with ``secret``."""
    a = secrets.randbelow(_MAX_OPERAND) + 1
    b = secrets.randbelow(_MAX_OPERAND) + 1
    ts = int(time.time())
    token = _sign(secret, ts=ts, a=a, b=b)
    return CaptchaChallenge(
        question=f"Combien font {a} + {b} ?",
        token=token,
    )


def verify_math_captcha(secret: str, token: str, answer: str) -> bool:
    """Return True if ``answer`` matches the signed challenge and it is not expired."""
    parsed = _parse_token(secret, token)
    if parsed is None:
        return False
    ts, a, b = parsed
    if int(time.time()) - ts > _CAPTCHA_TTL_SEC:
        return False
    try:
        value = int((answer or "").strip())
    except ValueError:
        return False
    return value == a + b


def _sign(secret: str, *, ts: int, a: int, b: int) -> str:
    payload = f"v1|{ts}|{a}|{b}|{a + b}"
    sig = hmac.new(
        (secret or "dev").encode("utf-8"),
        payload.encode("utf-8"),
        sha256,
    ).hexdigest()[:32]
    return f"v1.{ts}.{a}.{b}.{sig}"


def _parse_token(secret: str, token: str) -> tuple[int, int, int] | None:
    raw = (token or "").strip()
    parts = raw.split(".")
    if len(parts) != 5 or parts[0] != "v1":
        return None
    try:
        ts = int(parts[1])
        a = int(parts[2])
        b = int(parts[3])
    except ValueError:
        return None
    expected = _sign(secret, ts=ts, a=a, b=b)
    if not hmac.compare_digest(raw, expected):
        return None
    if a < 1 or b < 1 or a > _MAX_OPERAND or b > _MAX_OPERAND:
        return None
    return ts, a, b
