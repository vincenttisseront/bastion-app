"""Identity binding (fingerprint / IP subnet) + session hijack policies."""

from __future__ import annotations

from fastapi import Request
from fastapi.testclient import TestClient
from starlette.datastructures import Headers

from app.breakglass import COOKIE_NAME, issue_breakglass_token
from app.models import AuditLog, BreakGlassSession, SsoSessionAnchor
from app.security.identity_binding import (
    classify_drift,
    compute_fingerprint,
    compute_ip_subnet,
)
from app.security.session_binding_service import (
    ACTION_DRIFT,
    ACTION_HIJACK,
    evaluate_breakglass_binding,
    evaluate_sso_binding,
)
from app.sso_settings import Settings


def _settings(**kwargs) -> Settings:
    base = dict(
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="dedicated-bg-jwt-secret-v2xxxxxxxx",
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
    accept_language: str = "fr-FR",
    accept_encoding: str = "gzip",
    cookies: dict[str, str] | None = None,
) -> Request:
    headers = {
        "user-agent": ua,
        "accept-language": accept_language,
        "accept-encoding": accept_encoding,
        "x-real-ip": ip,
    }
    if cookies:
        headers["cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
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


def test_identity_binding_classify_and_subnet():
    assert compute_ip_subnet("203.0.113.45") == "203.0.113.0/24"
    assert compute_ip_subnet("2001:db8::1").endswith("/64")
    assert compute_ip_subnet("not-an-ip") == ""
    fp1 = compute_fingerprint("UA-A", "fr", "gzip")
    fp2 = compute_fingerprint("UA-B", "fr", "gzip")
    assert len(fp1) == 32
    assert fp1 != fp2
    assert classify_drift(True, True) == "none"
    assert classify_drift(True, False) == "weak"
    assert classify_drift(False, True) == "strong"
    assert classify_drift(False, False) == "strong"


def test_breakglass_same_ip_ua_no_mismatch(db_session):
    settings = _settings()
    req = _request()
    token, jti = issue_breakglass_token(
        db_session, "admin", settings.breakglass_jwt_secret, request=req
    )
    db_session.commit()
    row = db_session.query(BreakGlassSession).filter_by(jti=jti).first()
    assert row.first_ip_subnet == "203.0.113.0/24"
    assert row.first_fingerprint_hash

    ok = evaluate_breakglass_binding(
        db_session, _request(), jti=jti, username="admin"
    )
    db_session.commit()
    assert ok is True
    assert int(row.mismatch_count or 0) == 0
    assert not db_session.query(AuditLog).filter_by(action=ACTION_HIJACK).count()
    assert not db_session.query(AuditLog).filter_by(action=ACTION_DRIFT).count()
    assert token


def test_breakglass_strong_drift_returns_false_and_logs(db_session):
    settings = _settings()
    login_req = _request(ip="203.0.113.10", ua="Mozilla/5.0 A")
    _token, jti = issue_breakglass_token(
        db_session, "admin", settings.breakglass_jwt_secret, request=login_req
    )
    db_session.commit()

    attack = _request(ip="198.51.100.20", ua="Mozilla/5.0 Attacker")
    ok = evaluate_breakglass_binding(
        db_session, attack, jti=jti, username="admin"
    )
    db_session.commit()
    assert ok is False
    row = db_session.query(BreakGlassSession).filter_by(jti=jti).first()
    assert int(row.mismatch_count or 0) == 1
    entry = db_session.query(AuditLog).filter_by(action=ACTION_HIJACK).one()
    assert entry.details["family"] == "breakglass"
    assert entry.details["jti"] == jti
    assert entry.details["policy"] == "stepup_401"
    assert "203.0.113.0/24" == entry.details["expected_subnet"]
    assert "198.51.100.0/24" == entry.details["observed_subnet"]


def test_breakglass_weak_drift_allows_with_light_log(db_session):
    settings = _settings()
    login_req = _request(ip="203.0.113.10", ua="Mozilla/5.0 A")
    _token, jti = issue_breakglass_token(
        db_session, "admin", settings.breakglass_jwt_secret, request=login_req
    )
    db_session.commit()

    updated = _request(ip="203.0.113.99", ua="Mozilla/5.0 B-updated")
    ok = evaluate_breakglass_binding(
        db_session, updated, jti=jti, username="admin"
    )
    db_session.commit()
    assert ok is True
    assert not db_session.query(AuditLog).filter_by(action=ACTION_HIJACK).count()
    assert db_session.query(AuditLog).filter_by(action=ACTION_DRIFT).count() == 1


def test_breakglass_ip_only_change_is_strong(db_session):
    """Same fingerprint, different /24 → strong (stolen cookie + copied UA)."""
    settings = _settings()
    ua = "Mozilla/5.0 SameUA"
    _token, jti = issue_breakglass_token(
        db_session,
        "admin",
        settings.breakglass_jwt_secret,
        request=_request(ip="203.0.113.10", ua=ua),
    )
    db_session.commit()
    ok = evaluate_breakglass_binding(
        db_session,
        _request(ip="198.51.100.5", ua=ua),
        jti=jti,
        username="admin",
    )
    assert ok is False


def test_breakglass_warm_deploy_anchors_on_first_request(db_session):
    settings = _settings()
    _token, jti = issue_breakglass_token(
        db_session, "admin", settings.breakglass_jwt_secret
    )
    db_session.commit()
    row = db_session.query(BreakGlassSession).filter_by(jti=jti).first()
    assert row.first_ip_subnet is None

    ok = evaluate_breakglass_binding(
        db_session, _request(ip="203.0.113.10"), jti=jti, username="admin"
    )
    db_session.commit()
    assert ok is True
    db_session.refresh(row)
    assert row.first_ip_subnet == "203.0.113.0/24"
    assert not db_session.query(AuditLog).filter_by(action=ACTION_HIJACK).count()


def test_breakglass_oauth2_auth_401_on_strong_drift(client: TestClient, db_session):
    secret = "test-bg-jwt-secret"
    login_req = _request(ip="203.0.113.10", ua="Mozilla/5.0 A")
    token, jti = issue_breakglass_token(
        db_session, "admin", secret, request=login_req
    )
    db_session.commit()

    r1 = client.get(
        "/internal/oauth2-auth",
        headers={
            "X-Real-IP": "203.0.113.10",
            "User-Agent": "Mozilla/5.0 A",
            "Accept-Language": "fr-FR",
            "Accept-Encoding": "gzip",
            "Cookie": f"{COOKIE_NAME}={token}",
        },
    )
    assert r1.status_code == 200

    r2 = client.get(
        "/internal/oauth2-auth",
        headers={
            "X-Real-IP": "198.51.100.20",
            "User-Agent": "Mozilla/5.0 Attacker",
            "Accept-Language": "en-US",
            "Accept-Encoding": "br",
            "Cookie": f"{COOKIE_NAME}={token}",
        },
    )
    assert r2.status_code == 401
    row = db_session.query(BreakGlassSession).filter_by(jti=jti).first()
    assert int(row.mismatch_count or 0) >= 1
    assert db_session.query(AuditLog).filter_by(action=ACTION_HIJACK).count() >= 1


def test_sso_anchor_warn_only_on_strong_drift(db_session):
    cookie = "oauth2-session-cookie-value-xyz"
    first = _request(
        ip="203.0.113.10",
        ua="Mozilla/5.0 A",
        cookies={"_oauth2_proxy": cookie},
    )
    summary = evaluate_sso_binding(db_session, first, username="alice@example.com")
    db_session.commit()
    assert summary is not None
    assert summary["drift"] == "none"
    assert db_session.query(SsoSessionAnchor).count() == 1

    attack = _request(
        ip="198.51.100.20",
        ua="Mozilla/5.0 Attacker",
        cookies={"_oauth2_proxy": cookie},
    )
    summary2 = evaluate_sso_binding(
        db_session, attack, username="alice@example.com"
    )
    db_session.commit()
    assert summary2["drift"] == "strong"
    assert summary2["mismatch_count"] == 1
    entry = db_session.query(AuditLog).filter_by(action=ACTION_HIJACK).one()
    assert entry.details["family"] == "sso"
    assert entry.details["policy"] == "warn_only"
    # Cookie value never stored
    assert cookie not in str(entry.details)
    anchor = db_session.query(SsoSessionAnchor).one()
    assert cookie not in (anchor.cookie_hash or "")


def test_sso_warm_deploy_first_sight_no_mismatch(db_session):
    cookie = "existing-session-before-deploy"
    req = _request(cookies={"_oauth2_proxy": cookie})
    summary = evaluate_sso_binding(db_session, req, username="bob@example.com")
    db_session.commit()
    assert summary["mismatch_count"] == 0
    assert not db_session.query(AuditLog).filter_by(action=ACTION_HIJACK).count()
