"""Break-glass JWT absolute TTL + idle timeout."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

from app.breakglass import (
    COOKIE_MAX_AGE,
    IDLE_TIMEOUT_SECONDS,
    create_breakglass_token,
    decode_breakglass_token,
    encode_breakglass_claims,
    validate_breakglass_cookie,
)
from app.breakglass_cookie_middleware import _rotation_due

SECRET = "test-breakglass-secret-for-pytest"


def test_create_token_has_exp_and_last():
    token = create_breakglass_token("admin", SECRET)
    payload = jwt.decode(
        token, SECRET, algorithms=["HS256"], options={"verify_aud": False}
    )
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


def test_rotation_claims_slide_last_without_extending_exp():
    now = datetime.now(timezone.utc)
    original_exp = now + timedelta(seconds=COOKIE_MAX_AGE)
    payload = {
        "sub": "admin",
        "iat": int((now - timedelta(minutes=10)).timestamp()),
        "exp": int(original_exp.timestamp()),
        "last": int((now - timedelta(minutes=2)).timestamp()),
        "type": "bg",
        "jti": "old-jti",
    }
    rotated = encode_breakglass_claims(payload, SECRET, jti="new-jti")
    claims = jwt.decode(
        rotated, SECRET, algorithms=["HS256"], options={"verify_aud": False}
    )
    assert claims["sub"] == "admin"
    assert claims["jti"] == "new-jti"
    assert abs(claims["exp"] - original_exp.timestamp()) < 2
    assert claims["last"] >= int((now - timedelta(seconds=5)).timestamp())


def test_rotation_skipped_when_recently_touched():
    assert _rotation_due(create_breakglass_token("admin", SECRET)) is False


def test_rotation_due_after_min_interval():
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "admin",
            "iat": now - timedelta(minutes=10),
            "exp": now + timedelta(hours=1),
            "last": int((now - timedelta(minutes=2)).timestamp()),
            "type": "bg",
            "jti": "stale-jti",
        },
        SECRET,
        algorithm="HS256",
    )
    assert _rotation_due(token) is True
