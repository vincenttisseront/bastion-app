"""JWT audience (aud) on bastion_session and break-glass cookies."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
import pytest
from sqlalchemy.orm import Session

from app.breakglass import create_breakglass_token, decode_breakglass_token
from app.jwt_audience import (
    DEFAULT_BREAKGLASS_JWT_AUDIENCE,
    DEFAULT_OIDC_SESSION_JWT_AUDIENCE,
    jwt_audience_matches,
)
from app.models import OidcSession
from app.oidc_bff import (
    create_oidc_session_token,
    issue_oidc_session,
    validate_oidc_session_cookie,
)
from app.sso_settings import Settings

OIDC_SECRET = "oidc-session-hmac-key-32bytes-min!!"
BG_SECRET = "test-bg-jwt-secret-different!!"


def _settings(**kwargs) -> Settings:
    base = dict(
        environment="test",
        database_url="sqlite://",
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        oidc_session_jwt_secret=OIDC_SECRET,
        oidc_session_max_age=3600,
    )
    base.update(kwargs)
    return Settings(**base)


def test_jwt_audience_matches_legacy_without_aud():
    assert jwt_audience_matches({"sub": "x"}, "bastion-portal", strict=False) is True
    assert jwt_audience_matches({"sub": "x"}, "bastion-portal", strict=True) is False


def test_jwt_audience_matches_string_and_list():
    assert jwt_audience_matches({"aud": "bastion-portal"}, "bastion-portal") is True
    assert jwt_audience_matches({"aud": "other"}, "bastion-portal") is False
    assert jwt_audience_matches({"aud": ["a", "bastion-portal"]}, "bastion-portal") is True


def test_create_oidc_session_token_includes_aud():
    token = create_oidc_session_token(
        sub="sub-1",
        username="alice",
        realm="ar-systems",
        jti="jti-1",
        secret=OIDC_SECRET,
        max_age=3600,
    )
    payload = jwt.decode(
        token,
        OIDC_SECRET,
        algorithms=["HS256"],
        options={"verify_aud": False},
    )
    assert payload["aud"] == DEFAULT_OIDC_SESSION_JWT_AUDIENCE


def test_validate_oidc_session_rejects_wrong_aud(db_session: Session):
    jti = str(uuid4())
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "sub-1",
            "username": "alice",
            "realm": "ar-systems",
            "jti": jti,
            "iat": now,
            "exp": now + timedelta(hours=1),
            "type": "oidc",
            "aud": "wrong-audience",
        },
        OIDC_SECRET,
        algorithm="HS256",
    )
    db_session.add(
        OidcSession(
            jti=jti,
            sub="sub-1",
            username="alice",
            realm="ar-systems",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
    )
    db_session.commit()
    settings = _settings()
    assert validate_oidc_session_cookie(token, db=db_session, settings=settings) is None


def test_validate_oidc_session_accepts_legacy_without_aud(db_session: Session):
    jti = str(uuid4())
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "sub-1",
            "username": "alice",
            "realm": "ar-systems",
            "jti": jti,
            "iat": now,
            "exp": now + timedelta(hours=1),
            "type": "oidc",
        },
        OIDC_SECRET,
        algorithm="HS256",
    )
    db_session.add(
        OidcSession(
            jti=jti,
            sub="sub-1",
            username="alice",
            realm="ar-systems",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
    )
    db_session.commit()
    settings = _settings(oidc_session_jwt_audience_strict=False)
    assert validate_oidc_session_cookie(token, db=db_session, settings=settings) is not None


def test_validate_oidc_session_strict_rejects_legacy_without_aud(db_session: Session):
    jti = str(uuid4())
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "sub-1",
            "username": "alice",
            "realm": "ar-systems",
            "jti": jti,
            "iat": now,
            "exp": now + timedelta(hours=1),
            "type": "oidc",
        },
        OIDC_SECRET,
        algorithm="HS256",
    )
    db_session.add(
        OidcSession(
            jti=jti,
            sub="sub-1",
            username="alice",
            realm="ar-systems",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
    )
    db_session.commit()
    settings = _settings(oidc_session_jwt_audience_strict=True)
    assert validate_oidc_session_cookie(token, db=db_session, settings=settings) is None


def test_issue_oidc_session_emits_matching_aud(db_session: Session):
    settings = _settings()
    token, _jti = issue_oidc_session(
        db_session,
        sub="sub-1",
        username="alice",
        realm="ar-systems",
        secret=OIDC_SECRET,
        max_age=3600,
        audience=settings.oidc_session_jwt_audience,
    )
    db_session.commit()
    claims = validate_oidc_session_cookie(token, db=db_session, settings=settings)
    assert claims is not None
    payload = jwt.decode(
        token,
        OIDC_SECRET,
        algorithms=["HS256"],
        options={"verify_aud": False},
    )
    assert payload["aud"] == settings.oidc_session_jwt_audience


def test_breakglass_token_includes_aud():
    token = create_breakglass_token("admin", BG_SECRET)
    payload = jwt.decode(
        token,
        BG_SECRET,
        algorithms=["HS256"],
        options={"verify_aud": False},
    )
    assert payload["aud"] == DEFAULT_BREAKGLASS_JWT_AUDIENCE


def test_decode_breakglass_rejects_wrong_aud():
    token = create_breakglass_token("admin", BG_SECRET, audience="other-aud")
    assert (
        decode_breakglass_token(
            token,
            BG_SECRET,
            audience=DEFAULT_BREAKGLASS_JWT_AUDIENCE,
            audience_strict=True,
        )
        is None
    )


def test_decode_breakglass_accepts_legacy_without_aud_when_not_strict():
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "admin",
            "iat": now,
            "exp": now + timedelta(hours=1),
            "last": int(now.timestamp()),
            "type": "bg",
            "jti": "jti-bg-1",
        },
        BG_SECRET,
        algorithm="HS256",
    )
    payload = decode_breakglass_token(
        token,
        BG_SECRET,
        audience=DEFAULT_BREAKGLASS_JWT_AUDIENCE,
        audience_strict=False,
    )
    assert payload is not None
