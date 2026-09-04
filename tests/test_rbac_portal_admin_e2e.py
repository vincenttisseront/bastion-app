"""E2E: promote/revoke portal_admin via AccessGrant without Keycloak groups or break-glass."""

from __future__ import annotations

import pytest
import respx

from app.models import AccessGrant, AuditLog, RealmConfig
from app.rbac.grants_service import AccessGrantCreate, create_grant, list_users_with_direct_grants
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
    "X-User-Id": "kc-admin",
}

# Regular SSO user: no portal-admins group, no break-glass.
USER_HEADERS = {
    "X-Email": "bob@example.com",
    "X-Preferred-Username": "bob",
    "X-User": "bob",
    "X-User-Id": "kc-user-bob",
    "X-Groups": "ARSYSTEMS-Users",
}

KC_USER_ID = "kc-user-bob"


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


def test_non_admin_without_grant_is_denied(client):
    resp = client.get("/admin/rbac", headers=USER_HEADERS, follow_redirects=False)
    assert resp.status_code in (302, 403)
    apps = client.get("/apps", headers=USER_HEADERS)
    assert apps.status_code == 200
    assert "Administration" not in apps.text


def test_promote_and_revoke_portal_admin_via_grants_api(client, db_session):
    """Promote via POST /admin/rbac/grants (same path as the users UI form), then revoke."""
    before = client.get("/admin/dashboard", headers=USER_HEADERS, follow_redirects=False)
    assert before.status_code in (302, 403)

    create = client.post(
        "/admin/rbac/grants",
        headers={**ADMIN_HEADERS, "Accept": "application/json", "Content-Type": "application/json"},
        json={
            "subject_type": "user",
            "keycloak_user_id": KC_USER_ID,
            "user_display_cache": "bob",
            "resource_type": "system_role",
            "system_role": "portal_admin",
            "access_level": "view",
        },
    )
    assert create.status_code == 200, create.text
    grant_id = create.json()["grant"]["id"]
    assert db_session.query(AccessGrant).filter_by(id=grant_id).first() is not None

    audit = (
        db_session.query(AuditLog)
        .filter_by(action="rbac.grant.created")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.actor == "admin@example.com"

    promoted = client.get("/admin/dashboard", headers=USER_HEADERS)
    assert promoted.status_code == 200
    apps = client.get("/apps", headers=USER_HEADERS)
    assert apps.status_code == 200
    assert "Administration" in apps.text

    users_page = client.get(
        "/admin/rbac/users?list_tab=keycloak", headers=ADMIN_HEADERS
    )
    assert users_page.status_code == 200
    assert "bob" in users_page.text
    assert "Privilégié" in users_page.text
    assert "SSO avec accès" in users_page.text or "Recherche Keycloak" in users_page.text
    assert "Anomalies de Connexion" not in users_page.text

    revoke = client.post(
        f"/admin/rbac/grants/{grant_id}/delete",
        headers=ADMIN_HEADERS,
        data={"redirect_url": "/admin/rbac/users"},
        follow_redirects=False,
    )
    assert revoke.status_code in (302, 200)

    after = client.get("/admin/dashboard", headers=USER_HEADERS, follow_redirects=False)
    assert after.status_code in (302, 403)
    apps_after = client.get("/apps", headers=USER_HEADERS)
    assert "Administration" not in apps_after.text


@respx.mock
def test_promote_via_html_form_like_users_ui(client, db_session):
    """Simulate the HTML form posted from /admin/rbac/users (not JSON API)."""
    realm = _realm(db_session)
    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    user_url = f"https://kc.example.com/admin/realms/AR-SYSTEMS/users/{KC_USER_ID}"
    groups_url = f"{user_url}/groups"
    respx.post(token_url).respond(200, json={"access_token": "t"})
    respx.get(user_url).respond(
        200,
        json={"id": KC_USER_ID, "username": "bob", "email": "bob@example.com"},
    )
    respx.get(groups_url).respond(200, json=[])

    resp = client.post(
        "/admin/rbac/grants",
        headers=ADMIN_HEADERS,
        data={
            "subject_type": "user",
            "keycloak_user_id": KC_USER_ID,
            "user_display_cache": "bob",
            "resource_type": "system_role",
            "system_role": "portal_admin",
            "access_level": "view",
            "realm_id": str(realm.id),
            "redirect_url": f"/admin/rbac/users?realm_id={realm.id}&keycloak_user_id={KC_USER_ID}",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert KC_USER_ID in (resp.headers.get("location") or "")

    grant = (
        db_session.query(AccessGrant)
        .filter_by(keycloak_user_id=KC_USER_ID, system_role="portal_admin")
        .first()
    )
    assert grant is not None

    assert client.get("/admin/rbac", headers=USER_HEADERS).status_code == 200

    detail = client.get(
        f"/admin/rbac/users?realm_id={realm.id}&keycloak_user_id={KC_USER_ID}",
        headers=ADMIN_HEADERS,
    )
    assert detail.status_code == 200
    assert "Administrateur portail" in detail.text or "portal_admin" in detail.text


def test_list_users_with_direct_grants_helper(db_session):
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="u-1",
            user_display_cache="alice",
            resource_type="system_role",
            system_role="portal_admin",
            access_level="view",
        ),
        "admin",
    )
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="u-1",
            user_display_cache="alice",
            resource_type="system_role",
            system_role="portal_auditor",
            access_level="view",
        ),
        "admin",
    )
    db_session.commit()

    users = list_users_with_direct_grants(db_session)
    assert len(users) == 1
    assert users[0]["keycloak_user_id"] == "u-1"
    assert users[0]["grant_count"] == 2
    assert users[0]["has_portal_admin"] is True


@pytest.mark.asyncio
@respx.mock
async def test_list_sso_users_with_access_includes_group_members(db_session):
    from app.models import App, RBACGroup
    from app.rbac.grants_service import list_sso_users_with_access

    realm = _realm(db_session)
    app = App(slug="wiki", label="Wiki", upstream_url="https://wiki.internal/", enabled=True)
    db_session.add(app)
    db_session.flush()
    group = RBACGroup(
        name="ARSYSTEMS-Users",
        realm_id=realm.id,
        keycloak_group_id="kc-g-arsystems",
        path="/ARSYSTEMS-Users",
        member_count=1,
    )
    db_session.add(group)
    db_session.flush()
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="u-direct",
            user_display_cache="direct-only",
            resource_type="system_role",
            system_role="portal_auditor",
            access_level="view",
        ),
        "admin",
    )
    db_session.commit()

    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    respx.post(token_url).respond(200, json={"access_token": "t"})
    respx.get(url__regex=r".*/groups/kc-g-arsystems/members.*").respond(
        200,
        json=[
            {
                "id": "u-via-group",
                "username": "brigitte",
                "email": "brigitte@example.com",
            }
        ],
    )

    users = await list_sso_users_with_access(db_session, _settings(), realm_id=realm.id)
    by_id = {u["keycloak_user_id"]: u for u in users}
    assert "u-direct" in by_id
    assert "u-via-group" in by_id
    assert by_id["u-via-group"]["display"] == "brigitte"
    assert "ARSYSTEMS-Users" in by_id["u-via-group"]["via_groups"]
    assert "group" in by_id["u-via-group"]["access_via"]
    assert "direct" in by_id["u-direct"]["access_via"]


def test_oauth2_export_sets_user_id_claim_sub(db_session):
    from app.admin.export import generate_oauth2_proxy_config

    realm = _realm(db_session)
    cfg = generate_oauth2_proxy_config(realm, _settings())
    assert 'user_id_claim = "sub"' in cfg
