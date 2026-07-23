"""Break-glass JWT absolute TTL + idle timeout."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

from app.breakglass import (
    COOKIE_MAX_AGE,
    IDLE_TIMEOUT_SECONDS,
    create_breakglass_token,
    decode_breakglass_token,
    maybe_refresh_breakglass_cookie,
    validate_breakglass_cookie,
)


SECRET = "test-breakglass-secret-for-pytest"


def test_create_token_has_exp_and_last():
    token = create_breakglass_token("admin", SECRET)
    payload = jwt.decode(token, SECRET, algorithms=["HS256"])
    assert payload["sub"] == "admin"
    assert payload["type"] == "bg"
    assert "exp" in payload
    assert "last" in payload
    assert "iat" in payload
    assert "jti" in payload


def test_validate_rejects_expired_absolute():
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "admin",
            "iat": now - timedelta(hours=9),
            "exp": now - timedelta(hours=1),
            "last": int(now.timestamp()),
            "type": "bg",
            "jti": "expired-jti",
        },
        SECRET,
        algorithm="HS256",
    )
    assert validate_breakglass_cookie(token, SECRET) is False


def test_validate_rejects_idle_timeout():
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "admin",
            "iat": now - timedelta(hours=1),
            "exp": now + timedelta(hours=7),
            "last": int((now - timedelta(seconds=IDLE_TIMEOUT_SECONDS + 5)).timestamp()),
            "type": "bg",
            "jti": "idle-jti",
        },
        SECRET,
        algorithm="HS256",
    )
    assert decode_breakglass_token(token, SECRET) is None
    assert validate_breakglass_cookie(token, SECRET) is False


def test_validate_accepts_fresh_token():
    token = create_breakglass_token("admin", SECRET)
    assert validate_breakglass_cookie(token, SECRET) is True


def test_refresh_slides_last_without_extending_exp():
    now = datetime.now(timezone.utc)
    original_exp = now + timedelta(seconds=COOKIE_MAX_AGE)
    token = jwt.encode(
        {
            "sub": "admin",
            "iat": now - timedelta(minutes=10),
            "exp": original_exp,
            "last": int((now - timedelta(minutes=2)).timestamp()),
            "type": "bg",
            "jti": "refresh-jti",
        },
        SECRET,
        algorithm="HS256",
    )
    refreshed = maybe_refresh_breakglass_cookie(token, SECRET)
    assert refreshed is not None
    payload = jwt.decode(refreshed, SECRET, algorithms=["HS256"])
    assert payload["sub"] == "admin"
    assert payload["jti"] == "refresh-jti"
    # Absolute exp preserved (within 2s)
    new_exp = payload["exp"]
    if isinstance(new_exp, datetime):
        new_exp_ts = new_exp.timestamp()
    else:
        new_exp_ts = float(new_exp)
    assert abs(new_exp_ts - original_exp.timestamp()) < 2
    assert int(payload["last"]) >= int((now - timedelta(seconds=5)).timestamp())


def test_refresh_skipped_when_recently_touched():
    token = create_breakglass_token("admin", SECRET)
    assert maybe_refresh_breakglass_cookie(token, SECRET) is None
