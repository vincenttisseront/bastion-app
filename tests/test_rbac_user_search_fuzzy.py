"""RBAC user search — Keycloak candidates + stdlib fuzzy rank (Option A)."""

from __future__ import annotations

import pytest
import respx

from app.rbac.keycloak_admin import (
    score_user_against_query,
    search_keycloak_users_fuzzy,
)
from tests.test_access_grants import ADMIN_HEADERS, _realm, _settings


def test_score_user_typo_tolerance():
    user = {
        "id": "1",
        "username": "grafana-bot",
        "email": "grafana@example.com",
        "firstName": "Graf",
        "lastName": "Ana",
    }
    assert score_user_against_query("grafna", user) >= 0.52
    assert score_user_against_query("grafana", user) >= 0.9
    assert score_user_against_query("zzz", user) < 0.52


@pytest.mark.asyncio
@respx.mock
async def test_search_keycloak_users_fuzzy_typo(db_session):
    settings = _settings()
    realm = _realm(db_session)
    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    respx.post(token_url).respond(200, json={"access_token": "t"})

    # Native typo query returns nothing; prefix pool returns the real user.
    respx.get(
        "https://kc.example.com/admin/realms/AR-SYSTEMS/users?search=vincnet&max=20"
    ).respond(200, json=[])
    respx.get(
        "https://kc.example.com/admin/realms/AR-SYSTEMS/users?search=vi&max=100"
    ).respond(
        200,
        json=[
            {
                "id": "user-1",
                "username": "vincent.tisseront",
                "email": "vincent@example.com",
                "firstName": "Vincent",
                "lastName": "Tisseront",
            },
            {
                "id": "user-2",
                "username": "virgile",
                "email": "virgile@example.com",
            },
        ],
    )

    results = await search_keycloak_users_fuzzy(realm, "vincnet", settings, limit=8)
    assert results
    assert results[0]["username"] == "vincent.tisseront"


@pytest.mark.asyncio
async def test_search_keycloak_users_fuzzy_short_query(db_session):
    settings = _settings()
    realm = _realm(db_session)
    assert await search_keycloak_users_fuzzy(realm, "v", settings) == []
    assert await search_keycloak_users_fuzzy(realm, "", settings) == []


@respx.mock
def test_rbac_user_search_endpoint_fuzzy(client, db_session):
    settings = _settings()
    realm = _realm(db_session)
    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    respx.post(token_url).respond(200, json={"access_token": "t"})
    respx.get(
        "https://kc.example.com/admin/realms/AR-SYSTEMS/users?search=vincent&max=20"
    ).respond(
        200,
        json=[
            {
                "id": "user-1",
                "username": "vincent.tisseront",
                "email": "vincent@example.com",
            }
        ],
    )
    # Broad prefix call (same results OK)
    respx.get(
        "https://kc.example.com/admin/realms/AR-SYSTEMS/users?search=vi&max=100"
    ).respond(
        200,
        json=[
            {
                "id": "user-1",
                "username": "vincent.tisseront",
                "email": "vincent@example.com",
            }
        ],
    )

    resp = client.get(
        f"/admin/rbac/users/search?realm_id={realm.id}&q=vincent",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["users"][0]["username"] == "vincent.tisseront"


@respx.mock
def test_rbac_user_search_short_query_empty(client, db_session):
    realm = _realm(db_session)
    resp = client.get(
        f"/admin/rbac/users/search?realm_id={realm.id}&q=v",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "users": []}
