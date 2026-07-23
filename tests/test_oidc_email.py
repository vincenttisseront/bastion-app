"""Keycloak email recovery when oauth2-proxy omits X-Email."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.orm import Session

from app.models import RealmConfig
from app.rbac.oidc_email import (
    keycloak_email_diagnostics,
    looks_like_email,
    resolve_user_email,
)
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings
from app.web.user_context import UserContext


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
        sso_portal_default_realm_slug="ar-systems",
    )


def _user(**kwargs) -> UserContext:
    defaults = dict(
        email="herve.tisseront",
        username="herve.tisseront",
        groups=[],
        realm_slug="ar-systems",
        auth_source="sso",
        is_admin=False,
        keycloak_user_id="kc-herve",
    )
    defaults.update(kwargs)
    return UserContext(**defaults)


def _realm(db: Session) -> RealmConfig:
    settings = _settings()
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
        groups_sync_enabled=True,
        keycloak_admin_client_id="admin-cli",
        keycloak_admin_client_secret_encrypted=encrypt_secret("admin-secret", settings),
        last_test_status="ok",
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def test_looks_like_email():
    assert looks_like_email("herve.tisseront@ar-systems.fr")
    assert not looks_like_email("herve.tisseront")
    assert not looks_like_email("")


def test_keycloak_email_diagnostics_missing():
    diag = keycloak_email_diagnostics({"username": "herve.tisseront", "email": ""})
    assert diag["has_email"] is False
    assert diag["warning"]


def test_keycloak_email_diagnostics_unverified():
    diag = keycloak_email_diagnostics(
        {
            "username": "herve.tisseront",
            "email": "herve.tisseront@ar-systems.fr",
            "emailVerified": False,
        }
    )
    assert diag["has_email"] is True
    assert diag["email_verified"] is False
    assert "emailVerified=false" in (diag["warning"] or "")


@pytest.mark.asyncio
async def test_resolve_user_email_uses_keycloak_when_session_short(db_session: Session):
    _realm(db_session)
    user = _user()
    with patch(
        "app.rbac.oidc_email.fetch_keycloak_user",
        new=AsyncMock(
            return_value={
                "id": "kc-herve",
                "username": "herve.tisseront",
                "email": "herve.tisseront@ar-systems.fr",
                "emailVerified": False,
            }
        ),
    ):
        email = await resolve_user_email(db_session, _settings(), user)
    assert email == "herve.tisseront@ar-systems.fr"


@pytest.mark.asyncio
async def test_resolve_user_email_keeps_session_when_already_full(db_session: Session):
    user = _user(email="vincent.tisseront@ar-systems.fr")
    with patch(
        "app.rbac.oidc_email.fetch_keycloak_user",
        new=AsyncMock(side_effect=AssertionError("must not call Keycloak")),
    ):
        email = await resolve_user_email(db_session, _settings(), user)
    assert email == "vincent.tisseront@ar-systems.fr"
