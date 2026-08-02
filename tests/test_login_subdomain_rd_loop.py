"""Prevent portal /login bounce loop with subdomain auth_request 401."""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import RealmConfig
from app.oidc_bff import issue_oidc_session
from app.sso_settings import Settings, get_settings
from app.web.user_context import UserContext
from tests.test_auth_login_flow import _add_default_idp

OIDC_SECRET = "oidc-login-loop-hmac-key-32bytes-min!!"
TRANSFER_RD = "https://transfer.ar-systems.fr/WebInterface/new-ui/index.html"


def _native_settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        breakglass_jwt_secret_fallback_enabled=True,
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.ar-systems.fr",
        database_url="sqlite://",
        oauth2_proxy_default_url="http://127.0.0.1:4180",
        oidc_session_jwt_secret=OIDC_SECRET,
        oidc_session_cookie_name="bastion_session",
        oidc_session_max_age=3600,
        oidc_native_session_enabled_realms="ar-systems",
    )


def _enable_native_realm(db: Session) -> RealmConfig:
    realm = _add_default_idp(db)
    realm.oidc_native_session_enabled = True
    db.commit()
    return realm


def test_login_with_native_session_bounces_to_subdomain_and_sets_domain(
    client: TestClient, db_session: Session
):
    settings = _native_settings()
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings
    _enable_native_realm(db_session)
    token, _jti = issue_oidc_session(
        db_session,
        sub="kc-sub",
        username="alice",
        realm="ar-systems",
        secret=OIDC_SECRET,
        max_age=3600,
        groups=("ARSYSTEMS-Users",),
    )
    db_session.commit()

    resp = client.get(
        f"/auth/login?rd={TRANSFER_RD}",
        cookies={"bastion_session": token},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers.get("location") == TRANSFER_RD
    set_cookie = " ".join(resp.headers.get_list("set-cookie"))
    assert "bastion_session=" in set_cookie
    assert "Domain=ar-systems.fr" in set_cookie or "domain=ar-systems.fr" in set_cookie


def test_login_injected_user_without_subdomain_cookie_goes_to_apps(
    client: TestClient, db_session: Session
):
    """auth_request identity alone must not bounce to transfer (401 loop)."""
    settings = _native_settings()
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings
    _enable_native_realm(db_session)

    fake_user = UserContext(
        email="alice@example.com",
        username="alice",
        groups=["ARSYSTEMS-Users"],
        realm_slug="ar-systems",
        auth_source="sso",
        is_admin=False,
        keycloak_user_id="kc-sub",
    )
    with patch("app.web.pages.get_user_context", return_value=fake_user):
        resp = client.get(
            f"/login?rd={TRANSFER_RD}",
            follow_redirects=False,
        )

    assert resp.status_code == 302
    assert resp.headers.get("location") == "/apps"


def test_login_invalid_native_cookie_with_absolute_rd_shows_login_not_loop(
    client: TestClient, db_session: Session
):
    settings = _native_settings()
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings
    _enable_native_realm(db_session)

    resp = client.get(
        f"/auth/login?rd={TRANSFER_RD}",
        cookies={"bastion_session": "not-a-jwt"},
        follow_redirects=False,
    )
    # Must not 302 back to transfer; either login HTML or /apps.
    loc = resp.headers.get("location") or ""
    assert TRANSFER_RD not in loc
    if resp.status_code == 302:
        assert loc.startswith("/")
    else:
        assert resp.status_code == 200
        assert "connexion" in resp.text.lower() or "login" in resp.text.lower()
