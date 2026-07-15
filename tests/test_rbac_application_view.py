"""Application ↔ AccessGrant cross-view tests."""

import pytest
import respx

from app.models import AccessGrant, App, RBACGroup, RealmConfig
from app.rbac.grants_service import (
    AccessGrantCreate,
    build_application_access_view,
    count_grants_by_application,
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
        member_count=None,
    )
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


def _app(db, *, slug: str = "transfer", label: str = "Transfer") -> App:
    app = App(
        slug=slug,
        label=label,
        upstream_url="https://transfer.internal/",
        enabled=True,
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


@respx.mock
@pytest.mark.asyncio
async def test_rbac_application_view_lists_group_and_user_grants(db_session):
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
            resource_type="application",
            application_id=app.id,
            access_level="manage",
        ),
        "admin@test",
    )
    db_session.commit()

    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    members_url = (
        f"https://kc.example.com/admin/realms/AR-SYSTEMS/groups/{group.keycloak_group_id}/members"
    )
    respx.post(token_url).respond(200, json={"access_token": "t"})
    respx.get(members_url).respond(
        200,
        json=[
            {"id": user_id, "username": "vincent.tisseront", "enabled": True},
            {"id": "user-other", "username": "other", "enabled": True},
        ],
    )

    access = await build_application_access_view(db_session, app.id, settings)

    assert access["grant_count"] == 2
    types = {row["subject_type"] for row in access["grants"]}
    assert types == {"group", "user"}
    # same user via group + direct => one person; plus "user-other"
    assert access["unique_people_count"] == 2
    assert set(access["people_sources"][user_id]) == {"direct", f"via groupe {group.name}"}


def test_rbac_application_view_page(client, db_session):
    realm = _realm(db_session)
    group = _group(db_session, realm)
    app = _app(db_session)
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
    db_session.commit()

    resp = client.get(
        f"/admin/rbac/applications/{app.id}",
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 200
    assert "Qui a accès à cette application" in resp.text
    assert "ARSYSTEMS-Users" in resp.text
    assert "launch" in resp.text


def test_catalogue_grant_badge_count_matches_grants(client, db_session):
    realm = _realm(db_session)
    group = _group(db_session, realm)
    app = _app(db_session)
    other = _app(db_session, slug="wikijs", label="Wiki.js")

    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="application",
            application_id=app.id,
            access_level="view",
        ),
        "admin@test",
    )
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="u1",
            user_display_cache="alice",
            resource_type="application",
            application_id=app.id,
            access_level="manage",
        ),
        "admin@test",
    )
    db_session.commit()

    counts = count_grants_by_application(db_session)
    assert counts[app.id] == 2
    assert other.id not in counts

    resp = client.get("/catalogue", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert f"/admin/rbac/applications/{app.id}" in resp.text
    assert "2 droits" in resp.text
    assert "0 droit" in resp.text


def test_rbac_matrix_shows_group_level(client, db_session):
    realm = _realm(db_session)
    group = _group(db_session, realm)
    app = _app(db_session)
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
    db_session.commit()

    resp = client.get("/admin/rbac/matrix", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Matrice Applications" in resp.text
    assert "launch" in resp.text
    assert "ARSYSTEMS-Users" in resp.text
