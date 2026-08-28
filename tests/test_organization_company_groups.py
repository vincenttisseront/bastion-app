"""Company / organization group naming and fuzzy reuse."""

from __future__ import annotations

import pytest
import respx

from app.models import BastionAccount, RBACGroup
from app.rbac.account_service import ensure_company_group, find_rbac_company_group
from app.rbac.organization_names import normalize_organization_name, organization_match_key
from tests.test_bastion_account_creation import (
    ADMIN_HEADERS,
    JSON_HEADERS,
    KC_ADMIN,
    TOKEN_URL,
    _mock_no_duplicate,
    _realm,
    _settings,
)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("SDIS 81", "sdis81"),
        ("SDIS81", "sdis81"),
        ("SDIS_81", "sdis81"),
        ("SDIS-81", "sdis81"),
        ("/SDIS 81", "sdis81"),
        ("  SDIS..81  ", "sdis81"),
        ("", ""),
    ],
)
def test_organization_match_key(raw, expected):
    assert organization_match_key(raw) == expected


def test_normalize_organization_name_collapses_whitespace():
    assert normalize_organization_name("  SDIS   81  ") == "SDIS 81"


def test_find_rbac_company_group_fuzzy(db_session):
    realm = _realm(db_session)
    existing = RBACGroup(
        realm_id=realm.id,
        keycloak_group_id="kc-sdis81",
        name="SDIS81",
        path="/SDIS81",
        group_tag="Société",
    )
    db_session.add(existing)
    db_session.commit()

    hit = find_rbac_company_group(
        db_session, realm_id=realm.id, organization="SDIS 81"
    )
    assert hit is not None
    assert hit.id == existing.id
    assert hit.name == "SDIS81"


@respx.mock
@pytest.mark.asyncio
async def test_ensure_company_group_reuses_fuzzy_rbac(db_session):
    realm = _realm(db_session)
    existing = RBACGroup(
        realm_id=realm.id,
        keycloak_group_id="kc-sdis81",
        name="SDIS81",
        path="/SDIS81",
        group_tag="Société",
    )
    db_session.add(existing)
    db_session.commit()

    group = await ensure_company_group(
        db_session,
        _settings(),
        realm=realm,
        organization="SDIS_81",
        actor="admin@example.com",
    )
    assert group.id == existing.id
    assert (
        db_session.query(RBACGroup).filter(RBACGroup.realm_id == realm.id).count()
        == 1
    )


@respx.mock
@pytest.mark.asyncio
async def test_ensure_company_group_reuses_keycloak_fuzzy(db_session):
    realm = _realm(db_session)
    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    respx.get(f"{KC_ADMIN}/groups").respond(
        200,
        json=[
            {
                "id": "kc-existing",
                "name": "SDIS81",
                "path": "/SDIS81",
                "subGroups": [],
            }
        ],
    )

    group = await ensure_company_group(
        db_session,
        _settings(),
        realm=realm,
        organization="SDIS 81",
        actor="admin@example.com",
    )
    assert group.keycloak_group_id == "kc-existing"
    assert group.name == "SDIS81"
    assert group.group_tag == "Société"
    assert not any(
        r.request.method == "POST" and str(r.request.url).rstrip("/").endswith("/groups")
        for r in respx.calls
    )


@respx.mock
def test_create_account_with_variant_org_reuses_group(client, db_session):
    """POST /users/new with « SDIS 81 » reuses existing « SDIS81 » société group."""
    realm = _realm(db_session)
    existing = RBACGroup(
        realm_id=realm.id,
        keycloak_group_id="kc-sdis81",
        name="SDIS81",
        path="/SDIS81",
        group_tag="Société",
    )
    db_session.add(existing)
    db_session.commit()

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    _mock_no_duplicate()
    respx.post(f"{KC_ADMIN}/users").respond(
        201, headers={"Location": f"{KC_ADMIN}/users/kc-new-1"}
    )
    respx.put(f"{KC_ADMIN}/users/kc-new-1/groups/kc-sdis81").respond(204)

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data={
            "realm_id": str(realm.id),
            "username": "john.doe",
            "email": "john.doe@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "organization_pick": "",
            "organization": "SDIS 81",
            "reveal_password": "on",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    account = (
        db_session.query(BastionAccount)
        .filter_by(realm_id=realm.id, username="john.doe")
        .first()
    )
    assert account is not None
    assert account.organization == "SDIS81"
    assert (
        db_session.query(RBACGroup).filter(RBACGroup.realm_id == realm.id).count()
        == 1
    )


@respx.mock
def test_create_account_picks_existing_company_group(client, db_session):
    realm = _realm(db_session)
    existing = RBACGroup(
        realm_id=realm.id,
        keycloak_group_id="kc-sdis81",
        name="SDIS81",
        path="/SDIS81",
        group_tag="Société",
    )
    db_session.add(existing)
    db_session.commit()

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    _mock_no_duplicate(username="ada.test", email="ada@example.com")
    respx.post(f"{KC_ADMIN}/users").respond(
        201, headers={"Location": f"{KC_ADMIN}/users/kc-ada"}
    )
    respx.put(f"{KC_ADMIN}/users/kc-ada/groups/kc-sdis81").respond(204)

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data={
            "realm_id": str(realm.id),
            "username": "ada.test",
            "email": "ada@example.com",
            "first_name": "Ada",
            "last_name": "Test",
            "organization_pick": str(existing.id),
            "organization": "",
            "reveal_password": "on",
        },
    )
    assert resp.status_code == 200, resp.text
    account = (
        db_session.query(BastionAccount)
        .filter_by(realm_id=realm.id, username="ada.test")
        .first()
    )
    assert account is not None
    assert account.organization == "SDIS81"


def test_new_user_form_lists_company_groups(client, db_session):
    realm = _realm(db_session)
    db_session.add(
        RBACGroup(
            realm_id=realm.id,
            keycloak_group_id="kc-sdis81",
            name="SDIS81",
            path="/SDIS81",
            group_tag="Société",
        )
    )
    db_session.commit()

    resp = client.get("/admin/rbac/users/new", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert 'name="organization_pick"' in resp.text
    assert "Nouvelle société" in resp.text
    assert "Société existante" in resp.text
    assert "SDIS81" in resp.text
