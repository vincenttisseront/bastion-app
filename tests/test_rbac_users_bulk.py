"""Bulk users / group distribution scale helpers."""

from __future__ import annotations

import pytest

from app.models import BastionAccount, RBACGroup, RealmConfig
from app.rbac.users_bulk_service import (
    bastion_accounts_csv,
    resolve_bastion_account_ids,
)
from app.secret_crypto import encrypt_secret
from app.sso_settings import get_settings


ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _realm(db_session) -> RealmConfig:
    s = get_settings()
    realm = RealmConfig(
        slug="portal-bulk",
        name="Portal",
        issuer_url="https://kc.example.com/realms/portal",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.test/oauth2/portal/callback",
        oauth2_proxy_port=4180,
        groups_sync_enabled=True,
        provisioning_enabled=True,
    )
    db_session.add(realm)
    db_session.commit()
    return realm


def test_resolve_and_csv_export(db_session):
    realm = _realm(db_session)
    a1 = BastionAccount(
        realm_id=realm.id,
        username="alice",
        email="alice@example.com",
        organization="ACME",
        status="keycloak_created",
        origin="bastion",
        keycloak_user_id="kc-1",
        created_by="admin@example.com",
    )
    a2 = BastionAccount(
        realm_id=realm.id,
        username="bob",
        email="bob@example.com",
        organization="ACME",
        status="keycloak_created",
        origin="bastion",
        keycloak_user_id="kc-2",
        created_by="admin@example.com",
    )
    db_session.add_all([a1, a2])
    db_session.commit()

    ids = resolve_bastion_account_ids(
        db_session,
        account_ids=[a1.id, a2.id, a1.id],
        select_all_matching=False,
        q=None,
        realm_id=None,
        group_name=None,
        status_filter=None,
    )
    assert ids == [a1.id, a2.id]

    all_ids = resolve_bastion_account_ids(
        db_session,
        account_ids=[],
        select_all_matching=True,
        q="alice",
        realm_id=realm.id,
        group_name=None,
        status_filter=None,
    )
    assert all_ids == [a1.id]

    csv_text = bastion_accounts_csv(db_session, realm_id=realm.id)
    assert "alice" in csv_text
    assert "bob" in csv_text
    assert "username" in csv_text.splitlines()[0]


def test_users_page_group_dist_hides_empty(client, db_session):
    _realm(db_session)
    db_session.add_all(
        [
            RBACGroup(name="populated", member_count=3),
            RBACGroup(name="empty-one", member_count=0),
        ]
    )
    db_session.commit()
    resp = client.get("/admin/rbac/users?list_tab=bastion", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "populated" in resp.text
    assert "vides masqués" in resp.text or "masqués" in resp.text
    assert "empty-one" not in resp.text


def test_users_export_csv_route(client, db_session):
    realm = _realm(db_session)
    db_session.add(
        BastionAccount(
            realm_id=realm.id,
            username="carol",
            email="carol@example.com",
            status="keycloak_created",
            origin="bastion",
            keycloak_user_id="kc-3",
            created_by="admin@example.com",
        )
    )
    db_session.commit()
    resp = client.get(
        f"/admin/rbac/users/export.csv?realm_id={realm.id}",
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.headers.get("content-type", "")
    assert "carol" in resp.text
