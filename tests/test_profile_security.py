"""Self-service password change, session revoke, forgot password."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import OidcSession, RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings
from app.web.profile_security_service import (
    ProfileSecurityError,
    change_own_password,
    request_forgot_password,
)
from app.web.user_context import UserContext

USER_HEADERS = {
    "X-Email": "alice@example.com",
    "X-Preferred-Username": "alice",
    "X-User-Id": "kc-user-alice",
    "X-Groups": "team-ops",
}


def _realm(db: Session) -> RealmConfig:
    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
    )
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
        provisioning_enabled=True,
        keycloak_provision_client_id="bastion-admin-provision",
        keycloak_provision_client_secret_encrypted=encrypt_secret(
            "prov-secret", settings
        ),
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def _user() -> UserContext:
    return UserContext(
        email="alice@example.com",
        username="alice",
        keycloak_user_id="kc-user-alice",
        realm_slug="ar-systems",
        groups=["team-ops"],
        auth_source="sso",
        is_admin=False,
    )


def _csrf_from_profile(client: TestClient) -> str:
    page = client.get("/profile", headers=USER_HEADERS)
    match = re.search(r'name="csrf-token" content="([^"]+)"', page.text)
    assert match
    return match.group(1)


@pytest.mark.asyncio
async def test_change_own_password_rejects_short_password(db_session: Session):
    _realm(db_session)
    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
    )
    with pytest.raises(ProfileSecurityError, match="12"):
        await change_own_password(
            db_session,
            user=_user(),
            settings=settings,
            current_password="old-password-ok",
            new_password="short",
            confirm_password="short",
            actor="alice@example.com",
            ip_address="127.0.0.1",
        )


@pytest.mark.asyncio
async def test_change_own_password_happy_path(db_session: Session):
    _realm(db_session)
    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
    )
    with (
        patch(
            "app.web.profile_security_service.verify_keycloak_password",
            new_callable=AsyncMock,
        ) as verify,
        patch(
            "app.web.profile_security_service.reset_keycloak_password",
            new_callable=AsyncMock,
        ) as reset_pw,
    ):
        await change_own_password(
            db_session,
            user=_user(),
            settings=settings,
            current_password="Current-Pass-1234",
            new_password="New-Secure-Pass-99",
            confirm_password="New-Secure-Pass-99",
            actor="alice@example.com",
            ip_address="127.0.0.1",
        )
    verify.assert_awaited_once()
    reset_pw.assert_awaited_once()


def test_profile_password_post_success(client: TestClient, db_session: Session):
    _realm(db_session)
    csrf = _csrf_from_profile(client)
    with patch(
        "app.web.profile_security_service.change_own_password",
        new_callable=AsyncMock,
    ) as change_pw:
        resp = client.post(
            "/profile/password",
            data={
                "csrf_token": csrf,
                "current_password": "Current-Pass-1234",
                "new_password": "New-Secure-Pass-99",
                "confirm_password": "New-Secure-Pass-99",
            },
            headers=USER_HEADERS,
            follow_redirects=False,
        )
    assert resp.status_code == 302
    assert resp.headers["location"].endswith("/profile#section-security")
    change_pw.assert_awaited_once()


def test_profile_revoke_native_session(client: TestClient, db_session: Session):
    _realm(db_session)
    row = OidcSession(
        jti="other-jti",
        sub="kc-user-alice",
        username="alice",
        realm="ar-systems",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        revoked=False,
    )
    db_session.add(row)
    db_session.commit()
    csrf = _csrf_from_profile(client)
    resp = client.post(
        "/profile/sessions/revoke",
        data={
            "csrf_token": csrf,
            "session_kind": "portal_native",
            "session_id": "other-jti",
        },
        headers=USER_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    db_session.refresh(row)
    assert row.revoked is True


@pytest.mark.asyncio
async def test_forgot_password_always_generic(db_session: Session):
    _realm(db_session)
    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
    )
    with patch(
        "app.rbac.keycloak_admin.find_keycloak_user_by_identity",
        new_callable=AsyncMock,
        return_value=None,
    ):
        msg = await request_forgot_password(
            db_session,
            settings=settings,
            realm_slug="ar-systems",
            identity="unknown@example.com",
            ip_address="127.0.0.1",
        )
    assert "Si un compte correspond" in msg


def test_forgot_password_page_and_post(client: TestClient, db_session: Session):
    _realm(db_session)
    page = client.get("/auth/forgot-password")
    assert page.status_code == 200
    assert "Mot de passe oublié" in page.text
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert csrf
    with patch(
        "app.web.profile_security_service.request_forgot_password",
        new_callable=AsyncMock,
        return_value="Message générique de test.",
    ):
        resp = client.post(
            "/auth/forgot-password",
            data={
                "csrf_token": csrf.group(1),
                "identity": "alice@example.com",
                "realm": "ar-systems",
            },
            follow_redirects=False,
        )
    assert resp.status_code == 200
    assert "Message générique de test." in resp.text


def test_login_page_has_forgot_password_link(
    client: TestClient, db_session: Session, monkeypatch
):
    from app.main import app
    from app.sso_settings import get_settings

    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        oidc_native_session_enabled_realms="ar-systems",
    )
    get_settings.cache_clear()
    monkeypatch.setattr("app.oidc_bff.get_settings", lambda: settings)
    app.dependency_overrides[get_settings] = lambda: settings
    _realm(db_session)
    try:
        resp = client.get("/login")
        assert resp.status_code == 200
        assert "Mot de passe oublié" in resp.text
        assert "/auth/forgot-password" in resp.text
    finally:
        app.dependency_overrides.pop(get_settings, None)
        get_settings.cache_clear()
