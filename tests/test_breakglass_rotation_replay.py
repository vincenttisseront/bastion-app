"""Break-glass cookie rotation + replay detection (chain_id anti-replay)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from fastapi.testclient import TestClient
from starlette.datastructures import Headers
from fastapi import Request

from app.breakglass import (
    COOKIE_NAME,
    GRACE_WINDOW_SECONDS,
    issue_breakglass_token,
    list_breakglass_chains,
    process_breakglass_auth_request,
    revoke_breakglass_jti,
)
from app.models import AuditLog, BreakGlassSession
from app.sso_settings import Settings


SECRET = "test-bg-jwt-secret-rotation-32chars!!"


def _settings(**kwargs) -> Settings:
    base = dict(
        vault_portal_internal_token="legacy-token",
        breakglass_jwt_secret=SECRET,
        breakglass_jwt_secret_fallback_enabled=True,
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    base.update(kwargs)
    return Settings(**base)


def _request(
    *,
    ip: str = "203.0.113.10",
    ua: str = "Mozilla/5.0 TestBrowser/1.0",
    cookie: str | None = None,
) -> Request:
    headers = {
        "user-agent": ua,
        "accept-language": "fr-FR",
        "accept-encoding": "gzip",
        "x-real-ip": ip,
    }
    if cookie:
        headers["cookie"] = f"{COOKIE_NAME}={cookie}"
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": Headers(headers).raw,
        "client": ("127.0.0.1", 12345),
        "scheme": "https",
        "server": ("test", 443),
        "query_string": b"",
    }
    return Request(scope)


def test_login_creates_chain_and_rotation_advances(db_session):
    settings = _settings()
    req = _request()
    token, jti = issue_breakglass_token(
        db_session, "admin", SECRET, request=req
    )
    db_session.commit()
    row = db_session.query(BreakGlassSession).filter_by(jti=jti).first()
    assert row.chain_id == jti
    assert row.superseded_by is None

    result = process_breakglass_auth_request(
        db_session, _request(cookie=token), token, settings
    )
    db_session.commit()
    assert result.ok is True
    assert result.set_cookie
    assert result.jti != jti

    db_session.refresh(row)
    assert row.superseded_by == result.jti
    assert row.superseded_at is not None
    tip = db_session.query(BreakGlassSession).filter_by(jti=result.jti).first()
    assert tip.chain_id == jti
    assert tip.superseded_by is None

    # Absolute exp preserved
    old_payload = jwt.decode(token, SECRET, algorithms=["HS256"])
    new_payload = jwt.decode(result.set_cookie, SECRET, algorithms=["HS256"])
    assert int(new_payload["exp"]) == int(old_payload["exp"])


def test_grace_reuse_resyncs_without_cutting_chain(db_session):
    settings = _settings()
    token, jti = issue_breakglass_token(
        db_session, "admin", SECRET, request=_request()
    )
    db_session.commit()
    r1 = process_breakglass_auth_request(
        db_session, _request(cookie=token), token, settings
    )
    db_session.commit()
    assert r1.ok and r1.set_cookie

    # Immediate replay of OLD cookie → grace
    r2 = process_breakglass_auth_request(
        db_session, _request(cookie=token), token, settings
    )
    db_session.commit()
    assert r2.ok is True
    assert r2.set_cookie
    tip_payload = jwt.decode(r2.set_cookie, SECRET, algorithms=["HS256"])
    assert tip_payload["jti"] == r1.jti
    assert not any(
        bool(x.chain_revoked)
        for x in db_session.query(BreakGlassSession).filter_by(chain_id=jti)
    )
    assert db_session.query(AuditLog).filter_by(
        action="breakglass_cookie_grace_reuse"
    ).count() >= 1


def test_replay_outside_grace_cuts_entire_chain(db_session):
    settings = _settings()
    token, jti0 = issue_breakglass_token(
        db_session, "admin", SECRET, request=_request()
    )
    db_session.commit()
    r1 = process_breakglass_auth_request(
        db_session, _request(cookie=token), token, settings
    )
    db_session.commit()
    current_token = r1.set_cookie
    current_jti = r1.jti

    old_row = db_session.query(BreakGlassSession).filter_by(jti=jti0).first()
    old_row.superseded_at = utcnow_minus(seconds=GRACE_WINDOW_SECONDS + 2)
    db_session.commit()

    # Replay old cookie outside grace
    r2 = process_breakglass_auth_request(
        db_session, _request(cookie=token), token, settings
    )
    db_session.commit()
    assert r2.ok is False
    rows = db_session.query(BreakGlassSession).filter_by(chain_id=jti0).all()
    assert rows
    assert all(bool(r.chain_revoked) for r in rows)
    assert (
        db_session.query(AuditLog)
        .filter_by(action="breakglass_cookie_replay_detected")
        .count()
        >= 1
    )

    # Current legitimate jti also blocked
    r3 = process_breakglass_auth_request(
        db_session, _request(cookie=current_token), current_token, settings
    )
    assert r3.ok is False
    assert current_jti


def test_admin_revoke_non_current_cuts_tip(db_session):
    settings = _settings()
    token, jti0 = issue_breakglass_token(
        db_session, "admin", SECRET, request=_request()
    )
    db_session.commit()
    r1 = process_breakglass_auth_request(
        db_session, _request(cookie=token), token, settings
    )
    db_session.commit()
    tip_token = r1.set_cookie

    revoke_breakglass_jti(db_session, jti0, revoked_by="ops", reason="compromise")
    db_session.commit()

    r2 = process_breakglass_auth_request(
        db_session, _request(cookie=tip_token), tip_token, settings
    )
    assert r2.ok is False


def test_rotation_preserves_identity_anchors(db_session):
    settings = _settings()
    token, jti = issue_breakglass_token(
        db_session, "admin", SECRET, request=_request(ip="203.0.113.10")
    )
    db_session.commit()
    row = db_session.query(BreakGlassSession).filter_by(jti=jti).first()
    first_subnet = row.first_ip_subnet
    first_fp = row.first_fingerprint_hash
    assert first_subnet and first_fp

    r1 = process_breakglass_auth_request(
        db_session, _request(cookie=token, ip="203.0.113.10"), token, settings
    )
    db_session.commit()
    tip = db_session.query(BreakGlassSession).filter_by(jti=r1.jti).first()
    assert tip.first_ip_subnet == first_subnet
    assert tip.first_fingerprint_hash == first_fp
    assert tip.expires_at.replace(tzinfo=timezone.utc) == row.expires_at.replace(
        tzinfo=timezone.utc
    )


def test_multiple_rotations_preserve_absolute_exp(db_session):
    """Absolute JWT exp / DB expires_at must not move across many rotations."""
    settings = _settings()
    token, jti0 = issue_breakglass_token(
        db_session, "admin", SECRET, request=_request()
    )
    db_session.commit()
    initial_row = db_session.query(BreakGlassSession).filter_by(jti=jti0).first()
    initial_exp_db = initial_row.expires_at.replace(tzinfo=timezone.utc)
    initial_exp_jwt = int(
        jwt.decode(token, SECRET, algorithms=["HS256"])["exp"]
    )

    for i in range(5):
        result = process_breakglass_auth_request(
            db_session, _request(cookie=token), token, settings
        )
        db_session.commit()
        assert result.ok, f"rotation {i} failed"
        assert result.set_cookie
        token = result.set_cookie
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        assert int(payload["exp"]) == initial_exp_jwt
        tip = db_session.query(BreakGlassSession).filter_by(jti=result.jti).first()
        assert tip.expires_at.replace(tzinfo=timezone.utc) == initial_exp_db
        assert tip.chain_id == jti0

    members = db_session.query(BreakGlassSession).filter_by(chain_id=jti0).all()
    assert len(members) == 6  # initial + 5 rotations
    assert all(
        m.expires_at.replace(tzinfo=timezone.utc) == initial_exp_db for m in members
    )


def test_purge_removes_whole_chain_together(db_session):
    """
    Purge is keyed on the newest expires_at of a chain.

    A superseded member past the cutoff must NOT be deleted alone while the tip
    is still within retention — and when the tip is past cutoff, every member goes.
    """
    from app.breakglass import purge_expired_breakglass_sessions
    from app.models import utcnow

    now = utcnow()
    # Chain keep: tip still fresh → orphan-prone old member must stay.
    keep_chain = "chain-keep"
    db_session.add_all(
        [
            BreakGlassSession(
                jti="keep-old",
                chain_id=keep_chain,
                username="admin",
                issued_at=now - timedelta(days=20),
                expires_at=now - timedelta(days=20),
                revoked=False,
                chain_revoked=False,
                superseded_by="keep-tip",
                superseded_at=now - timedelta(days=15),
            ),
            BreakGlassSession(
                jti="keep-tip",
                chain_id=keep_chain,
                username="admin",
                issued_at=now - timedelta(days=15),
                expires_at=now + timedelta(hours=2),
                revoked=False,
                chain_revoked=False,
            ),
        ]
    )
    # Chain drop: tip past retention → whole chain purged together.
    drop_chain = "chain-drop"
    db_session.add_all(
        [
            BreakGlassSession(
                jti="drop-old",
                chain_id=drop_chain,
                username="admin",
                issued_at=now - timedelta(days=30),
                expires_at=now - timedelta(days=25),
                revoked=False,
                chain_revoked=False,
                superseded_by="drop-tip",
                superseded_at=now - timedelta(days=20),
            ),
            BreakGlassSession(
                jti="drop-tip",
                chain_id=drop_chain,
                username="admin",
                issued_at=now - timedelta(days=20),
                expires_at=now - timedelta(days=10),
                revoked=False,
                chain_revoked=False,
            ),
        ]
    )
    db_session.commit()

    deleted = purge_expired_breakglass_sessions(db_session, retention_days=7)
    assert deleted == 2
    remaining = {
        r.jti for r in db_session.query(BreakGlassSession).all()
    }
    assert remaining == {"keep-old", "keep-tip"}
    assert "drop-old" not in remaining
    assert "drop-tip" not in remaining


def test_warm_deploy_missing_chain_id(db_session):
    settings = _settings()
    token, jti = issue_breakglass_token(db_session, "admin", SECRET)
    db_session.commit()
    row = db_session.query(BreakGlassSession).filter_by(jti=jti).first()
    row.chain_id = None
    db_session.commit()

    result = process_breakglass_auth_request(
        db_session, _request(cookie=token), token, settings
    )
    db_session.commit()
    assert result.ok is True
    db_session.refresh(row)
    assert row.chain_id == jti
    assert row.superseded_by == result.jti


def test_list_chains_groups_rotations(db_session):
    settings = _settings()
    token, jti = issue_breakglass_token(
        db_session, "admin", SECRET, request=_request()
    )
    db_session.commit()
    for _ in range(3):
        r = process_breakglass_auth_request(
            db_session, _request(cookie=token), token, settings
        )
        db_session.commit()
        assert r.ok
        token = r.set_cookie

    chains = list_breakglass_chains(db_session)
    assert len(chains) == 1
    assert chains[0]["chain_id"] == jti
    assert chains[0]["rotation_count"] == 3
    assert chains[0]["status"] == "active"


def test_oauth2_auth_does_not_rotate_cookie(client: TestClient, db_session):
    """auth_request must not rotate: nginx does not forward Set-Cookie."""
    token, jti = issue_breakglass_token(
        db_session, "admin", "test-bg-jwt-secret", request=_request()
    )
    db_session.commit()
    r1 = client.get(
        "/internal/oauth2-auth",
        headers={
            "X-Real-IP": "203.0.113.10",
            "User-Agent": "Mozilla/5.0 TestBrowser/1.0",
            "Accept-Language": "fr-FR",
            "Accept-Encoding": "gzip",
            "Cookie": f"{COOKIE_NAME}={token}",
        },
    )
    assert r1.status_code == 200
    set_cookie = r1.headers.get("set-cookie") or ""
    assert COOKIE_NAME not in set_cookie
    row = db_session.query(BreakGlassSession).filter_by(jti=jti).first()
    assert row.superseded_by is None


def test_portal_page_rotates_breakglass_cookie(client: TestClient, db_session):
    token, jti = issue_breakglass_token(
        db_session, "admin", "test-bg-jwt-secret", request=_request()
    )
    db_session.commit()
    r = client.get(
        "/admin/apps/create",
        headers={
            "X-Real-IP": "203.0.113.10",
            "User-Agent": "Mozilla/5.0 TestBrowser/1.0",
            "Accept-Language": "fr-FR",
            "Accept-Encoding": "gzip",
            "Cookie": f"{COOKIE_NAME}={token}",
        },
    )
    assert r.status_code == 200
    set_cookie = r.headers.get("set-cookie") or ""
    assert COOKIE_NAME in set_cookie
    db_session.expire_all()
    row = db_session.query(BreakGlassSession).filter_by(jti=jti).first()
    assert row.superseded_by is not None


def utcnow_minus(*, seconds: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)
