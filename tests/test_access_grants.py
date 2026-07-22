"""AccessGrant model, API, and effective rights tests."""

import pytest
import respx
from httpx import Response
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from app.models import AccessGrant, App, RBACGroup, RealmConfig
from app.rbac.grants_service import (
    AccessGrantCreate,
    compute_effective_grants,
    create_grant,
)
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )


def _realm(db) -> RealmConfig:
    s = _settings()
    realm = RealmConfig(
        slug="ar-systems",
        name="AR-SYSTEMS",
        issuer_url="https://kc.example.com/realms/AR-SYSTEMS",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.test/oauth2/ar-systems/callback",
        oauth2_proxy_port=4180,
        enabled=True,
        groups_sync_enabled=True,
        keycloak_admin_client_id="sync-client",
        keycloak_admin_client_secret_encrypted=encrypt_secret("admin-secret", s),
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def _group(db, realm: RealmConfig, *, kc_id: str = "g1", name: str = "ARSYSTEMS-Users") -> RBACGroup:
    group = RBACGroup(
        realm_id=realm.id,
        keycloak_group_id=kc_id,
        name=name,
        path=f"/{name}",
    )
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


def _app(db) -> App:
    app = App(
        slug="wikijs",
        label="Wiki.js",
        upstream_url="https://wiki.internal/",
        enabled=True,
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def test_access_grant_create_rejects_both_subjects():
    with pytest.raises(ValidationError):
        AccessGrantCreate.model_validate(
            {
                "subject_type": "group",
                "rbac_group_id": 1,
                "keycloak_user_id": "u1",
                "resource_type": "application",
                "application_id": 1,
            }
        )


def test_access_grant_create_rejects_no_subject():
    with pytest.raises(ValidationError):
        AccessGrantCreate.model_validate(
            {
                "subject_type": "user",
                "resource_type": "application",
                "application_id": 1,
            }
        )


def test_access_grant_db_check_rejects_invalid_subject(db_session):
    realm = _realm(db_session)
    group = _group(db_session, realm)
    app = _app(db_session)
    grant = AccessGrant(
        subject_type="group",
        rbac_group_id=group.id,
        keycloak_user_id="should-not-be-set",
        resource_type="application",
        application_id=app.id,
        granted_by="admin@test",
    )
    db_session.add(grant)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@respx.mock
@pytest.mark.asyncio
async def test_effective_grants_merge_group_and_direct(db_session):
    settings = _settings()
    realm = _realm(db_session)
    group = _group(db_session, realm)
    app = _app(db_session)
    user_id = "user-2465"

    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin@test",
    )
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id=user_id,
            user_display_cache="vincent.tisseront",
            resource_type="system_role",
            system_role="portal_auditor",
            access_level="view",
        ),
        "admin@test",
    )
    db_session.commit()

    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    groups_url = f"https://kc.example.com/admin/realms/AR-SYSTEMS/users/{user_id}/groups"
    respx.post(token_url).respond(200, json={"access_token": "t"})
    respx.get(groups_url).respond(200, json=[{"id": group.keycloak_group_id, "name": group.name}])

    effective = await compute_effective_grants(db_session, realm, user_id, settings)

    assert len(effective) == 2
    sources = {item["source"] for item in effective}
    assert "direct" in sources
    assert any(s.startswith("via groupe") for s in sources)
    roles = {item.get("system_role") for item in effective}
    assert "portal_auditor" in roles
    assert any(item.get("application_id") == app.id for item in effective)


@respx.mock
def test_user_search_mocked(client, db_session):
    settings = _settings()
    realm = _realm(db_session)
    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    search_url = "https://kc.example.com/admin/realms/AR-SYSTEMS/users?search=vincent&max=20"
    prefix_url = "https://kc.example.com/admin/realms/AR-SYSTEMS/users?search=vi&max=100"
    respx.post(token_url).respond(200, json={"access_token": "t"})
    payload = [
        {
            "id": "user-1",
            "username": "vincent.tisseront",
            "email": "vincent@example.com",
        }
    ]
    respx.get(search_url).respond(200, json=payload)
    respx.get(prefix_url).respond(200, json=payload)

    resp = client.get(
        f"/admin/rbac/users/search?realm_id={realm.id}&q=vincent",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["users"][0]["username"] == "vincent.tisseront"


def test_create_grant_via_api(client, db_session):
    realm = _realm(db_session)
    group = _group(db_session, realm)
    app = _app(db_session)

    resp = client.post(
        "/admin/rbac/grants",
        headers={**ADMIN_HEADERS, "Accept": "application/json", "Content-Type": "application/json"},
        json={
            "subject_type": "group",
            "rbac_group_id": group.id,
            "resource_type": "application",
            "application_id": app.id,
            "access_level": "view",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["grant"]["access_level"] == "view"
    assert db_session.query(AccessGrant).count() == 1
