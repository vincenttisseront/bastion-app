"""A persistent Keycloak 401 on an Admin API read explains what to check."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.models import RealmConfig
from app.rbac.keycloak_admin import fetch_keycloak_user, fetch_user_groups
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

KC_BASE = "https://kc.example.com"
TOKEN_URL = f"{KC_BASE}/realms/EXAMPLE-CORP/protocol/openid-connect/token"
USER_URL = f"{KC_BASE}/admin/realms/EXAMPLE-CORP/users/u-1"


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )


def _realm() -> RealmConfig:
    return RealmConfig(
        slug="example-corp",
        name="EXAMPLE-CORP",
        issuer_url=f"{KC_BASE}/realms/EXAMPLE-CORP",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", _settings()),
        redirect_uri="https://portal.test/oauth2/example-corp/callback",
        oauth2_proxy_port=4180,
        enabled=True,
        keycloak_admin_client_id="bastion-admin-sync",
        keycloak_admin_client_secret_encrypted=encrypt_secret("sync", _settings()),
    )


@respx.mock
@pytest.mark.asyncio
async def test_persistent_401_after_retry_gives_an_actionable_error():
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 300})
    )
    user_route = respx.get(USER_URL).mock(return_value=httpx.Response(401))

    with pytest.raises(ValueError) as exc:
        await fetch_keycloak_user(_realm(), "u-1", _settings())
    message = str(exc.value)
    assert "HTTP 401" in message and "issuer" in message
    assert user_route.call_count == 2  # one try + exactly one retry


@respx.mock
@pytest.mark.asyncio
async def test_other_statuses_keep_the_plain_message():
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 300})
    )
    respx.get(f"{USER_URL}/groups").mock(return_value=httpx.Response(500))

    with pytest.raises(ValueError) as exc:
        await fetch_user_groups(_realm(), "u-1", _settings())
    assert str(exc.value) == "Échec lecture groupes utilisateur (HTTP 500)"
