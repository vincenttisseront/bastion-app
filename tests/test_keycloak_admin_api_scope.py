"""Keycloak 26.8.2+ audience check on the Admin REST API.

A service-account token without the ``kc-admin-api`` client scope is refused
with a bare 401. The error must name the client and the fix. The RBAC users
stats never use the signed-in admin's identity: a break-glass session (no
Keycloak token at all) gets the same realm service-account calls as SSO.
"""

from __future__ import annotations

import base64
import html
import json

import httpx
import pytest
import respx

from app.auth.breakglass import COOKIE_NAME, issue_breakglass_token
from app.models import RealmConfig
from app.rbac.keycloak_admin import (
    KC_ADMIN_API_SCOPE,
    clear_admin_token_cache,
    count_keycloak_users,
    fetch_keycloak_groups,
    logout_keycloak_user,
)
from app.rbac.users_stats_service import clear_user_stats_cache
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

KC_BASE = "https://kc.example.com"
ISSUER = f"{KC_BASE}/realms/EXAMPLE-CORP"
TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"
ADMIN_URL = f"{KC_BASE}/admin/realms/EXAMPLE-CORP"
SYNC_CLIENT = "bastion-admin-sync"
# breakglass_jwt_secret of the ``client`` fixture settings (tests/conftest.py).
BG_SECRET = "test-bg-jwt-secret"


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )


def _jwt(**claims) -> str:
    def segment(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{segment({'alg': 'RS256', 'typ': 'JWT'})}.{segment(claims)}.signature"


NO_SCOPE = _jwt(iss=ISSUER, azp=SYNC_CLIENT, scope="profile email")
WITH_SCOPE = _jwt(iss=ISSUER, azp=SYNC_CLIENT, scope=f"profile {KC_ADMIN_API_SCOPE} email")


def _realm() -> RealmConfig:
    s = _settings()
    return RealmConfig(
        slug="example-corp",
        name="EXAMPLE-CORP",
        issuer_url=ISSUER,
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.test/oauth2/example-corp/callback",
        oauth2_proxy_port=4180,
        enabled=True,
        groups_sync_enabled=True,
        keycloak_admin_client_id=SYNC_CLIENT,
        keycloak_admin_client_secret_encrypted=encrypt_secret("sync", s),
    )


def _mint(token: str) -> respx.Route:
    return respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": token, "expires_in": 300})
    )


@pytest.fixture(autouse=True)
def _clean_caches():
    clear_admin_token_cache()
    clear_user_stats_cache()
    yield
    clear_admin_token_cache()
    clear_user_stats_cache()


# --- Admin API 401 diagnosis ------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_401_without_admin_api_scope_names_the_client_and_the_fix():
    _mint(NO_SCOPE)
    count = respx.get(f"{ADMIN_URL}/users/count").mock(return_value=httpx.Response(401))

    with pytest.raises(ValueError) as exc:
        await count_keycloak_users(_realm(), _settings())

    message = str(exc.value)
    assert message.startswith("Échec comptage utilisateurs (HTTP 401) : le token du client")
    assert f"« {SYNC_CLIENT} »" in message
    assert f"« {KC_ADMIN_API_SCOPE} »" in message and "26.8.2" in message
    assert count.call_count == 2  # the fresh token retry did not help


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("issuer", "issuer_note"),
    [
        (ISSUER, None),
        (
            "http://keycloak:8080/realms/EXAMPLE-CORP",
            (
                "Issuer du token : http://keycloak:8080/realms/EXAMPLE-CORP ; "
                f"realm appelé : {ISSUER}."
            ),
        ),
    ],
)
async def test_401_with_admin_api_scope_falls_back_to_keycloak_side_checks(
    issuer, issuer_note
):
    _mint(_jwt(iss=issuer, azp=SYNC_CLIENT, scope=KC_ADMIN_API_SCOPE))
    respx.get(f"{ADMIN_URL}/users/count").mock(return_value=httpx.Response(401))

    with pytest.raises(ValueError) as exc:
        await count_keycloak_users(_realm(), _settings())

    message = str(exc.value)
    assert "ne porte pas" not in message
    assert f"Keycloak a refusé le token du client « {SYNC_CLIENT} »" in message
    assert "journaux Keycloak" in message
    if issuer_note:
        assert message.endswith(issuer_note)
    else:
        assert "Issuer du token" not in message


@respx.mock
@pytest.mark.asyncio
async def test_groups_sync_401_explains_and_drops_the_rejected_token():
    tokens = _mint(NO_SCOPE)
    respx.get(url__startswith=f"{ADMIN_URL}/groups").mock(return_value=httpx.Response(401))
    realm = _realm()

    for _ in range(2):
        with pytest.raises(ValueError) as exc:
            await fetch_keycloak_groups(realm, _settings())
        assert str(exc.value).startswith("Échec lecture groupes Keycloak (HTTP 401) : ")
        assert f"« {KC_ADMIN_API_SCOPE} »" in str(exc.value)

    assert tokens.call_count == 2  # second sync did not reuse the refused token


@respx.mock
@pytest.mark.asyncio
async def test_admin_api_write_401_gets_the_same_explanation():
    _mint(NO_SCOPE)
    respx.post(f"{ADMIN_URL}/users/u-1/logout").mock(return_value=httpx.Response(401))

    with pytest.raises(ValueError) as exc:
        await logout_keycloak_user(_realm(), "u-1", _settings())

    assert str(exc.value).startswith("Échec logout Keycloak Admin API (HTTP 401) : ")
    assert f"« {KC_ADMIN_API_SCOPE} »" in str(exc.value)


# --- RBAC users page under break-glass ---------------------------------------


def _breakglass_admin(client, db_session) -> None:
    """Local emergency login: bg_session cookie only, no SSO identity headers."""
    db_session.add(_realm())
    token, _jti = issue_breakglass_token(db_session, "admin", BG_SECRET)
    db_session.commit()
    client.cookies.set(COOKIE_NAME, token)


@respx.mock
def test_breakglass_admin_gets_keycloak_stats_via_the_service_account(client, db_session):
    _breakglass_admin(client, db_session)
    _mint(WITH_SCOPE)
    totals = {None: 12, "true": 10, "false": 2}
    counts = respx.get(f"{ADMIN_URL}/users/count").mock(
        side_effect=lambda request: httpx.Response(
            200, json=totals[request.url.params.get("enabled")]
        )
    )

    resp = client.get("/admin/rbac/users?list_tab=open", follow_redirects=False)

    assert resp.status_code == 200
    assert "Stats Keycloak" not in resp.text
    assert '<div class="users-stat-value">12</div>' in resp.text
    assert '<div class="users-stat-value">10</div>' in resp.text
    assert counts.call_count == 3
    assert {c.request.headers["Authorization"] for c in counts.calls} == {
        f"Bearer {WITH_SCOPE}"
    }


@respx.mock
def test_breakglass_stats_banner_explains_the_missing_scope(client, db_session):
    _breakglass_admin(client, db_session)
    _mint(NO_SCOPE)
    respx.get(f"{ADMIN_URL}/users/count").mock(return_value=httpx.Response(401))

    resp = client.get("/admin/rbac/users?list_tab=open", follow_redirects=False)

    assert resp.status_code == 200
    text = html.unescape(resp.text)
    assert "Stats Keycloak : Échec comptage utilisateurs (HTTP 401) : le token du client" in text
    assert f"« {SYNC_CLIENT} »" in text and f"« {KC_ADMIN_API_SCOPE} »" in text
