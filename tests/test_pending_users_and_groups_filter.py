"""Pending first-login users + groups sync include filter."""

from __future__ import annotations

from datetime import timedelta

import pytest
import respx

from app.models import AccessGrant, ActiveSession, PendingUser, RBACGroup, RealmConfig, utcnow
from app.rbac.keycloak_admin import group_matches_sync_include, parse_groups_sync_include
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings
from app.web.pending_user_service import (
    acknowledge_pending_user,
    discover_recent_first_logins,
    record_first_login_if_new,
)

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def test_parse_and_match_groups_sync_include():
    assert parse_groups_sync_include("") == []
    assert parse_groups_sync_include("ARSYSTEMS-Users\n/Societes") == [
        "ARSYSTEMS-Users",
        "/Societes",
    ]
    assert group_matches_sync_include("ARSYSTEMS-Users", "/ARSYSTEMS-Users", []) is True
    assert group_matches_sync_include(
        "ARSYSTEMS-Users", "/ARSYSTEMS-Users", ["ARSYSTEMS Users"]
    )
    assert group_matches_sync_include("ABIOM", "/Societes/ABIOM", ["/Societes"])
    assert not group_matches_sync_include("other", "/other", ["ARSYSTEMS-Users"])


def test_record_first_login_only_on_new_session(db_session):
    row = record_first_login_if_new(
        db_session,
        user_email="carol@example.com",
        username="brigitte",
        realm_slug="example-corp",
        source_ip="1.2.3.4",
        is_new_session_row=True,
    )
    db_session.commit()
    assert row is not None
    assert row.status == "pending"

    again = record_first_login_if_new(
        db_session,
        user_email="carol@example.com",
        username="brigitte",
        realm_slug="example-corp",
        source_ip="1.2.3.4",
        is_new_session_row=False,
    )
    db_session.commit()
    assert again is not None
    assert again.hit_count == 2

    acknowledge_pending_user(
        db_session, user_id=row.id, actor="admin@example.com", status="approved"
    )
    db_session.commit()
    assert (
        record_first_login_if_new(
            db_session,
            user_email="carol@example.com",
            username="brigitte",
            realm_slug="example-corp",
            source_ip="1.2.3.4",
            is_new_session_row=True,
        )
        is None
    )


def test_discover_skips_uuid_duplicate_and_known_grants(db_session):
    now = utcnow()
    # Known Bastion user (vincent) — email + UUID session twins
    db_session.add(
        AccessGrant(
            subject_type="user",
            keycloak_user_id="e189ed16-79f8-4fa1-85ee-1bb7ff28852e",
            user_display_cache="alice.martin@example.com",
            resource_type="system_role",
            system_role="portal_admin",
            access_level="manage",
            granted_by="seed",
        )
    )
    for email, uname, sid in (
        (
            "alice.martin@example.com",
            "alice.martin",
            "u:alice@example-corp",
        ),
        (
            "e189ed16-79f8-4fa1-85ee-1bb7ff28852e",
            "alice.martin",
            "u:vincent-uuid",
        ),
        (
            "carol.petit@example.com",
            "carol.petit",
            "u:brigitte",
        ),
        (
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "carol.petit",
            "u:brigitte-uuid",
        ),
    ):
        db_session.add(
            ActiveSession(
                id=sid,
                kind="user",
                user_email=email,
                username=uname,
                realm="example-corp",
                protocol="oidc",
                target="portal",
                status="active",
                started_at=now - timedelta(minutes=10),
                last_seen_at=now,
            )
        )
    # Spurious pending rows already in DB (production state)
    db_session.add(
        PendingUser(
            user_email="alice.martin@example.com",
            username="alice.martin",
            realm_slug="example-corp",
            status="pending",
        )
    )
    db_session.add(
        PendingUser(
            user_email="e189ed16-79f8-4fa1-85ee-1bb7ff28852e",
            username="alice.martin",
            realm_slug="example-corp",
            status="pending",
        )
    )
    db_session.commit()

    created = discover_recent_first_logins(db_session, within_hours=168)
    db_session.commit()

    pending = (
        db_session.query(PendingUser).filter_by(status="pending").order_by(PendingUser.id).all()
    )
    emails = [p.user_email for p in pending]
    assert "alice.martin@example.com" not in emails
    assert not any("e189ed16" in e for e in emails)
    assert not any("aaaaaaaa" in e for e in emails)
    assert emails == ["carol.petit@example.com"]
    assert created >= 0


def test_record_skips_known_bastion_user(db_session):
    db_session.add(
        AccessGrant(
            subject_type="user",
            keycloak_user_id="kc-herve",
            user_display_cache="bob.durand@example.com",
            resource_type="system_role",
            system_role="portal_admin",
            access_level="view",
            granted_by="seed",
        )
    )
    db_session.commit()
    assert (
        record_first_login_if_new(
            db_session,
            user_email="bob.durand@example.com",
            username="bob.durand",
            realm_slug="example-corp",
            source_ip="1.1.1.1",
            is_new_session_row=True,
        )
        is None
    )


def test_breakglass_never_enters_pending_queue(db_session):
    """Break-glass is local emergency auth — not an SSO first-login candidate."""
    assert (
        record_first_login_if_new(
            db_session,
            user_email="admin@breakglass.local",
            username="admin",
            realm_slug="example-corp",
            source_ip="10.0.0.1",
            is_new_session_row=True,
        )
        is None
    )

    now = utcnow()
    db_session.add(
        PendingUser(
            user_email="admin@breakglass.local",
            username="admin",
            realm_slug="example-corp",
            status="pending",
            hit_count=3,
        )
    )
    db_session.add(
        ActiveSession(
            id="portal:admin@breakglass.local:example-corp",
            kind="user",
            user_email="admin@breakglass.local",
            username="admin",
            realm="example-corp",
            protocol="BREAKGLASS",
            target="portal",
            status="active",
            started_at=now - timedelta(minutes=5),
            last_seen_at=now,
        )
    )
    db_session.commit()

    created = discover_recent_first_logins(db_session, within_hours=168)
    db_session.commit()
    assert created == 0
    assert (
        db_session.query(PendingUser)
        .filter_by(user_email="admin@breakglass.local")
        .first()
        is None
    )


def test_pending_users_page_and_approve(client, db_session):
    db_session.add(
        PendingUser(
            user_email="carol@example.com",
            username="brigitte",
            realm_slug="example-corp",
            status="pending",
            hit_count=1,
        )
    )
    db_session.commit()
    resp = client.get("/admin/pending-users", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "carol@example.com" in resp.text
    assert "nouvelle connexion" in resp.text

    approve = client.post(
        "/admin/pending-users/1/approve",
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )
    assert approve.status_code == 302
    row = db_session.query(PendingUser).filter_by(user_email="carol@example.com").one()
    assert row.status == "approved"


@respx.mock
def test_sync_respects_groups_include_filter(client, db_session):
    from app.admin.throttling import reset_test_rate_limits

    reset_test_rate_limits()
    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )
    realm = RealmConfig(
        slug="kc-filter",
        name="KC",
        issuer_url="https://kc.example.com/realms/demo",
        client_id="login",
        client_secret_encrypted=encrypt_secret("s", settings),
        redirect_uri="https://portal.test/oauth2/kc-filter/callback",
        scopes="openid profile email",
        oauth2_proxy_port=4191,
        keycloak_admin_client_id="sync",
        keycloak_admin_client_secret_encrypted=encrypt_secret("admin", settings),
        groups_sync_enabled=True,
        groups_sync_include="ARSYSTEMS-Users",
    )
    db_session.add(realm)
    db_session.commit()

    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    groups_re = r"https://kc\.example\.com/admin/realms/demo/groups(?:\?.*)?$"
    children_re = r"https://kc\.example\.com/admin/realms/demo/groups/[^/?]+/children.*"
    respx.post(token_url).respond(
        200, json={"access_token": "t"}, headers={"content-type": "application/json"}
    )
    respx.get(url__regex=groups_re).respond(
        200,
        json=[
            {"id": "1", "name": "ARSYSTEMS-Users", "path": "/ARSYSTEMS-Users"},
            {"id": "2", "name": "ABIOM", "path": "/Societes/ABIOM"},
        ],
    )
    respx.get(url__regex=children_re).respond(200, json=[])
    respx.get(
        "https://kc.example.com/admin/realms/demo/groups/1/members?max=500"
    ).respond(
        200,
        json=[
            {"id": "u1", "email": "a@example.com"},
            {"id": "u2", "email": "b@example.com"},
            {"id": "u3", "email": "c@example.com"},
        ],
    )

    resp = client.post(
        f"/admin/rbac/groups/sync/{realm.id}",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"] == 1
    assert data["skipped"] == 1
    assert data["members_refreshed"] == 1
    assert data["members_total"] == 3
    group = db_session.query(RBACGroup).filter_by(realm_id=realm.id).one()
    assert group.name == "ARSYSTEMS-Users"
    assert group.member_count == 3


@respx.mock
@pytest.mark.asyncio
async def test_sync_refreshes_members_without_include_allowlist(db_session):
    """member_count must refresh even when groups_sync_include is empty (sync all)."""
    from app.rbac.keycloak_admin import sync_keycloak_groups

    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )
    realm = RealmConfig(
        slug="kc-all",
        name="KC",
        issuer_url="https://kc.example.com/realms/demo",
        client_id="login",
        client_secret_encrypted=encrypt_secret("s", settings),
        redirect_uri="https://portal.test/oauth2/kc-all/callback",
        scopes="openid profile email",
        oauth2_proxy_port=4192,
        keycloak_admin_client_id="sync",
        keycloak_admin_client_secret_encrypted=encrypt_secret("admin", settings),
        groups_sync_enabled=True,
        groups_sync_include="",
    )
    db_session.add(realm)
    db_session.commit()

    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    groups_re = r"https://kc\.example\.com/admin/realms/demo/groups(?:\?.*)?$"
    children_re = r"https://kc\.example\.com/admin/realms/demo/groups/[^/?]+/children.*"
    respx.post(token_url).respond(
        200, json={"access_token": "t"}, headers={"content-type": "application/json"}
    )
    respx.get(url__regex=groups_re).respond(
        200,
        json=[
            {"id": "10", "name": "TeamA", "path": "/TeamA"},
            {"id": "11", "name": "TeamB", "path": "/TeamB"},
        ],
    )
    respx.get(url__regex=children_re).respond(200, json=[])
    respx.get(
        "https://kc.example.com/admin/realms/demo/groups/10/members?max=500"
    ).respond(200, json=[{"id": "u1"}, {"id": "u2"}])
    respx.get(
        "https://kc.example.com/admin/realms/demo/groups/11/members?max=500"
    ).respond(200, json=[{"id": "u3"}])

    data = await sync_keycloak_groups(realm, db_session, settings)
    db_session.commit()
    assert data["imported"] == 2
    assert data["skipped"] == 0
    assert data["members_refreshed"] == 2
    assert data["members_total"] == 3
    counts = {
        g.name: g.member_count
        for g in db_session.query(RBACGroup).filter_by(realm_id=realm.id).all()
    }
    assert counts == {"TeamA": 2, "TeamB": 1}
    slugs = {
        g.name: g.realm_slug
        for g in db_session.query(RBACGroup).filter_by(realm_id=realm.id).all()
    }
    assert slugs == {"TeamA": realm.slug, "TeamB": realm.slug}
