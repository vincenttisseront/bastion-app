"""Break-glass jti denylist — individual session revocation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
import respx
from httpx import Response
from sqlalchemy.orm import Session

from app.breakglass import (
    COOKIE_NAME,
    COOKIE_MAX_AGE,
    IDLE_TIMEOUT_SECONDS,
    create_breakglass_token,
    decode_breakglass_token,
    issue_breakglass_token,
    maybe_refresh_breakglass_cookie,
    purge_expired_breakglass_sessions,
    register_breakglass_session,
    revoke_breakglass_jti,
    validate_breakglass_cookie,
)
from app.breakglass_store import set_breakglass_password
from app.models import AuditLog, BreakGlassSession, RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings, get_settings


SECRET = "test-breakglass-secret-for-pytest-32b"


def test_create_token_includes_jti():
    token = create_breakglass_token("admin", SECRET)
    payload = jwt.decode(token, SECRET, algorithms=["HS256"])
    assert payload["jti"]
    assert payload["type"] == "bg"


def test_legacy_token_without_jti_rejected():
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "admin",
            "iat": now,
            "exp": now + timedelta(hours=1),
            "last": int(now.timestamp()),
            "type": "bg",
        },
        SECRET,
        algorithm="HS256",
    )
    assert decode_breakglass_token(token, SECRET) is not None
    assert validate_breakglass_cookie(token, SECRET) is False


def test_issue_registers_session_and_validate_with_db(db_session: Session):
    token, jti = issue_breakglass_token(db_session, "admin", SECRET)
    db_session.commit()
    row = db_session.query(BreakGlassSession).filter_by(jti=jti).first()
    assert row is not None
    assert row.username == "admin"
    assert row.revoked is False
    assert validate_breakglass_cookie(token, SECRET, db=db_session) is True


def test_revoke_jti_blocks_next_validation(db_session: Session):
    token, jti = issue_breakglass_token(db_session, "admin", SECRET)
    db_session.commit()
    revoke_breakglass_jti(db_session, jti, revoked_by="ops", reason="compromise")
    db_session.commit()
    assert validate_breakglass_cookie(token, SECRET, db=db_session) is False


def test_refresh_preserves_jti(db_session: Session):
    now = datetime.now(timezone.utc)
    jti = "fixed-jti-for-refresh-test"
    token = jwt.encode(
        {
            "sub": "admin",
            "iat": now - timedelta(minutes=10),
            "exp": now + timedelta(seconds=COOKIE_MAX_AGE),
            "last": int((now - timedelta(minutes=2)).timestamp()),
            "type": "bg",
            "jti": jti,
        },
        SECRET,
        algorithm="HS256",
    )
    register_breakglass_session(
        db_session,
        jti=jti,
        username="admin",
        expires_at=now + timedelta(seconds=COOKIE_MAX_AGE),
    )
    db_session.commit()
    refreshed = maybe_refresh_breakglass_cookie(token, SECRET, db=db_session)
    assert refreshed is not None
    payload = jwt.decode(refreshed, SECRET, algorithms=["HS256"])
    assert payload["jti"] == jti


def test_idle_still_enforced_with_jti():
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
    assert validate_breakglass_cookie(token, SECRET) is False


def test_purge_removes_old_expired_rows(db_session: Session):
    old = BreakGlassSession(
        jti="old-jti",
        username="admin",
        issued_at=datetime.now(timezone.utc) - timedelta(days=20),
        expires_at=datetime.now(timezone.utc) - timedelta(days=10),
        revoked=True,
    )
    fresh = BreakGlassSession(
        jti="fresh-jti",
        username="admin",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        revoked=False,
    )
    db_session.add_all([old, fresh])
    db_session.commit()
    deleted = purge_expired_breakglass_sessions(db_session, retention_days=7)
    assert deleted == 1
    assert db_session.query(BreakGlassSession).filter_by(jti="fresh-jti").first()
    assert db_session.query(BreakGlassSession).filter_by(jti="old-jti").first() is None


def _admin_headers() -> dict[str, str]:
    return {
        "X-Email": "admin@example.com",
        "X-Preferred-Username": "admin",
        "X-Groups": "portal-admins",
    }


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token=SECRET,
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
        rfc1918_bypass_enabled=False,
        oauth2_proxy_default_url="http://127.0.0.1:4180",
    )


@respx.mock
def test_api_revoke_then_oauth2_auth_401(client, db_session: Session):
    settings = _settings()
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings
    set_breakglass_password(db_session, "bg-admin", "CorrectHorseBattery1")
    realm = RealmConfig(
        slug="ar-systems",
        name="AR-SYSTEMS",
        issuer_url="https://kc.example.com/realms/AR-SYSTEMS",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", settings),
        redirect_uri="https://portal.test/oauth2/ar-systems/callback",
        oauth2_proxy_port=4180,
        is_default=True,
        enabled=True,
        last_test_status="ok",
    )
    db_session.add(realm)
    db_session.commit()

    login = client.post(
        "/api/admin/breakglass/login",
        json={"username": "bg-admin", "password": "CorrectHorseBattery1"},
    )
    assert login.status_code == 200
    token = login.cookies.get(COOKIE_NAME)
    assert token
    payload = jwt.decode(token, SECRET, algorithms=["HS256"])
    jti = payload["jti"]

    respx.get("http://127.0.0.1:4180/oauth2/auth").mock(return_value=Response(401))
    ok = client.get("/internal/oauth2-auth", cookies={COOKIE_NAME: token})
    assert ok.status_code == 200

    rev = client.post(
        f"/api/admin/breakglass/sessions/{jti}/revoke",
        headers=_admin_headers(),
        json={"reason": "test revoke"},
    )
    assert rev.status_code == 200

    denied = client.get("/internal/oauth2-auth", cookies={COOKIE_NAME: token})
    assert denied.status_code == 401

    entry = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "breakglass_session_revoked")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert entry is not None
    assert entry.details["jti"] == jti


def test_api_revoke_unknown_jti_404(client, db_session: Session):
    set_breakglass_password(db_session, "admin", "CorrectHorseBattery1")
    resp = client.post(
        "/api/admin/breakglass/sessions/does-not-exist/revoke",
        headers=_admin_headers(),
    )
    assert resp.status_code == 404
