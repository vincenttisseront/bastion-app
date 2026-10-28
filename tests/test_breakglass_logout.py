"""GET /logout must revoke and clear break-glass sessions (Secure cookie flags)."""

from __future__ import annotations

from fastapi import Response
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth.breakglass import COOKIE_NAME
from app.auth.breakglass_store import set_breakglass_password
from app.auth.mfa_cookie import MFA_COOKIE_NAME
from app.models import BreakGlassSession
from app.session_cookies import OAUTH2_PROXY_COOKIE_NAMES, clear_browser_auth_cookies
from tests.test_auth_login_flow import _add_default_idp


def test_portal_logout_clears_breakglass_secure_cookie(
    client: TestClient, db_session: Session
):
    """Regression: Secure bg_session survived logout → /auth/login bounced to /apps."""
    _add_default_idp(db_session)
    set_breakglass_password(db_session, "admin", "super-secret-password")

    login = client.post(
        "/auth/breakglass",
        data={"username": "admin", "password": "super-secret-password", "rd": "/apps"},
        headers={"X-Real-IP": "10.0.0.50"},
        follow_redirects=False,
    )
    assert login.status_code == 302
    assert COOKIE_NAME in login.cookies
    token = login.cookies[COOKIE_NAME]
    client.cookies.set(COOKIE_NAME, token)

    row = db_session.query(BreakGlassSession).filter_by(revoked=False).one()

    logout = client.get("/logout", follow_redirects=False)
    assert logout.status_code == 302
    loc = logout.headers.get("location") or ""
    assert loc.startswith("/oauth2/") and "/sign_out" in loc
    assert "rd=/auth/login" in loc or "rd=%2Fauth%2Flogin" in loc
    set_cookie = " ".join(logout.headers.get_list("set-cookie")).lower()
    assert "bg_session=" in set_cookie
    assert "secure" in set_cookie
    assert "max-age=0" in set_cookie or "expires=" in set_cookie
    # oauth2 cookie kept for sign_out hop (IdP end_session).
    assert "_oauth2_proxy=" not in set_cookie
    assert f"{MFA_COOKIE_NAME}=" in set_cookie

    db_session.refresh(row)
    assert row.revoked is True

    # Stale cookie must not keep an authenticated redirect.
    bounce = client.get(
        "/auth/login",
        cookies={COOKIE_NAME: token},
        headers={"X-Real-IP": "10.0.0.50"},
        follow_redirects=False,
    )
    assert bounce.status_code == 200
    assert not (bounce.headers.get("location") or "").startswith("/apps")


def test_clear_browser_auth_cookies_covers_oauth2_and_mfa_with_domain():
    """API logout expires oauth2-proxy + MFA with Secure and parent Domain."""
    from app.sso_settings import Settings

    settings = Settings(
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.example.com",
        database_url="sqlite://",
    )
    response = Response()
    clear_browser_auth_cookies(response, settings, include_oauth2=True)
    jar = " ".join(response.headers.getlist("set-cookie")).lower()
    for name in OAUTH2_PROXY_COOKIE_NAMES:
        assert f"{name}=" in jar
    assert f"{MFA_COOKIE_NAME}=" in jar
    assert "bastion_session=" in jar
    assert "bg_session=" in jar
    assert "secure" in jar
    assert "domain=example.com" in jar
    assert "domain=.example.com" in jar


def test_oauth2_sign_out_path_sanitizes_slug_and_rd():
    from app.session_cookies import oauth2_sign_out_path

    assert oauth2_sign_out_path("default") == "/oauth2/default/sign_out?rd=/auth/login"
    assert oauth2_sign_out_path("../evil") == "/oauth2/evil/sign_out?rd=/auth/login"
    assert oauth2_sign_out_path("ok", rd="https://evil.example") == (
        "/oauth2/ok/sign_out?rd=/auth/login"
    )


def test_set_breakglass_cookie_shares_parent_domain_with_subdomains():
    """bg_session must reach wikijs.* like bastion_session (Domain=parent)."""
    from app.auth.breakglass import COOKIE_NAME, set_breakglass_cookie
    from app.sso_settings import Settings

    settings = Settings(
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.example.com",
        database_url="sqlite://",
    )
    response = Response()
    set_breakglass_cookie(response, "tok-value", settings)
    set_cookie = (response.headers.get("set-cookie") or "").lower()
    assert COOKIE_NAME in set_cookie
    assert "domain=example.com" in set_cookie
