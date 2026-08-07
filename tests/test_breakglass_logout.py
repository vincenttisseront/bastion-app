"""GET /logout must revoke and clear break-glass sessions (Secure cookie flags)."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.breakglass import COOKIE_NAME
from app.breakglass_store import set_breakglass_password
from app.models import BreakGlassSession
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
    assert logout.headers.get("location") == "/auth/login"
    set_cookie = " ".join(logout.headers.get_list("set-cookie")).lower()
    assert "bg_session=" in set_cookie
    assert "secure" in set_cookie
    assert "max-age=0" in set_cookie or "expires=" in set_cookie

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


def test_set_breakglass_cookie_shares_parent_domain_with_subdomains():
    """bg_session must reach wikijs.* like bastion_session (Domain=parent)."""
    from fastapi import Response

    from app.breakglass import COOKIE_NAME, set_breakglass_cookie
    from app.sso_settings import Settings

    settings = Settings(
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.ar-systems.fr",
        database_url="sqlite://",
    )
    response = Response()
    set_breakglass_cookie(response, "tok-value", settings)
    set_cookie = (response.headers.get("set-cookie") or "").lower()
    assert COOKIE_NAME in set_cookie
    assert "domain=ar-systems.fr" in set_cookie
