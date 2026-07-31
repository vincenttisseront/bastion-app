"""Pending first-login users + groups sync include filter."""

from __future__ import annotations

from datetime import timedelta

import pytest
import respx

from app.models import ActiveSession, PendingUser, RBACGroup, RealmConfig, utcnow
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
        "ARSYSTEMS-Users", "/ARSYSTEMS-Users", ["ARSYSTEMS-Users"]
    )
    assert group_matches_sync_include("ABIOM", "/Societes/ABIOM", ["/Societes"])
    assert not group_matches_sync_include("other", "/other", ["ARSYSTEMS-Users"])


def test_record_first_login_only_on_new_session(db_session):
    row = record_first_login_if_new(
        db_session,
        user_email="brigitte@ar-systems.fr",
        username="brigitte",
        realm_slug="ar-systems",
        source_ip="1.2.3.4",
        is_new_session_row=True,
    )
    db_session.commit()
    assert row is not None
    assert row.status == "pending"

    again = record_first_login_if_new(
        db_session,
        user_email="brigitte@ar-systems.fr",
        username="brigitte",
        realm_slug="ar-systems",
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
            user_email="brigitte@ar-systems.fr",
            username="brigitte",
            realm_slug="ar-systems",
            source_ip="1.2.3.4",
            is_new_session_row=True,
        )
        is None
    )


def test_discover_recent_first_logins(db_session):
    now = utcnow()
    db_session.add(
        ActiveSession(
            id="u:brigitte@ar-systems.fr:ar-systems",
            kind="user",
            user_email="brigitte@ar-systems.fr",
            username="brigitte",
            realm="ar-systems",
            protocol="oidc",
            target="portal",
            status="active",
            started_at=now - timedelta(minutes=20),
            last_seen_at=now,
        )
    )
    db_session.add(
        ActiveSession(
            id="u:old@ar-systems.fr:ar-systems",
            kind="user",
            user_email="old@ar-systems.fr",
            username="old",
            realm="ar-systems",
            protocol="oidc",
            target="portal",
            status="active",
            started_at=now - timedelta(days=30),
            last_seen_at=now - timedelta(days=1),
        )
    )
    db_session.commit()
    created = discover_recent_first_logins(db_session, within_hours=168)
    db_session.commit()
    assert created == 1
    pending = db_session.query(PendingUser).filter_by(status="pending").all()
    assert len(pending) == 1
    assert pending[0].user_email == "brigitte@ar-systems.fr"


def test_pending_users_page_and_approve(client, db_session):
    db_session.add(
        PendingUser(
            user_email="brigitte@ar-systems.fr",
            username="brigitte",
            realm_slug="ar-systems",
            status="pending",
            hit_count=1,
        )
    )
    db_session.commit()
    resp = client.get("/admin/pending-users", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "brigitte@ar-systems.fr" in resp.text
    assert "nouvelle connexion" in resp.text

    approve = client.post(
        "/admin/pending-users/1/approve",
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )
    assert approve.status_code == 302
    row = db_session.query(PendingUser).filter_by(user_email="brigitte@ar-systems.fr").one()
    assert row.status == "approved"


@respx.mock
def test_sync_respects_groups_include_filter(client, db_session):
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
    groups_url = "https://kc.example.com/admin/realms/demo/groups?briefRepresentation=false"
    respx.post(token_url).respond(
        200, json={"access_token": "t"}, headers={"content-type": "application/json"}
    )
    respx.get(groups_url).respond(
        200,
        json=[
            {"id": "1", "name": "ARSYSTEMS-Users", "path": "/ARSYSTEMS-Users"},
            {"id": "2", "name": "ABIOM", "path": "/Societes/ABIOM"},
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
    names = {g.name for g in db_session.query(RBACGroup).filter_by(realm_id=realm.id).all()}
    assert names == {"ARSYSTEMS-Users"}
