"""Unit tests for RBAC users list pagination helpers."""

from __future__ import annotations

from app.models import BastionAccount, RealmConfig
from app.rbac.users_list_service import (
    clamp_page_size,
    filter_import_users,
    paginate_list,
    query_bastion_accounts,
)
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings


def _settings() -> Settings:
    return Settings(
        environment="test",
        portal_domain="portal.test",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        vault_portal_internal_token="vault-token",
        breakglass_jwt_secret="bg-secret",
    )


def _realm(db, slug: str = "clients") -> RealmConfig:
    row = RealmConfig(
        slug=slug,
        name=slug.upper(),
        issuer_url=f"https://kc.test/realms/{slug}",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", _settings()),
        redirect_uri=f"https://portal.test/oauth2/{slug}/callback",
        oauth2_proxy_port=4180 + len(slug),
        enabled=True,
        provisioning_enabled=True,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def test_clamp_page_size():
    assert clamp_page_size(None) == 25
    assert clamp_page_size(0) == 1
    assert clamp_page_size(200) == 100


def test_paginate_list():
    items = list(range(30))
    page, meta = paginate_list(items, page=2, page_size=10)
    assert page == list(range(10, 20))
    assert meta["total"] == 30
    assert meta["page"] == 2
    assert meta["total_pages"] == 3


def test_filter_import_users():
    users = [
        {"display": "Alice Dupont", "keycloak_user_id": "a1"},
        {"display": "Bob", "keycloak_user_id": "b2"},
    ]
    assert len(filter_import_users(users, q="ali")) == 1
    assert filter_import_users(users, q="") == users


def test_query_bastion_accounts_paginated(db_session):
    realm = _realm(db_session)
    for i in range(30):
        db_session.add(
            BastionAccount(
                realm_id=realm.id,
                username=f"user{i:02d}",
                email=f"user{i:02d}@example.com",
                organization="SDIS 81" if i % 2 == 0 else "Other",
                status="keycloak_created",
                origin="bastion",
                created_by="admin@example.com",
            )
        )
    db_session.commit()

    rows, meta = query_bastion_accounts(db_session, page=1, page_size=10)
    assert len(rows) == 10
    assert meta["total"] == 30
    assert meta["total_pages"] == 3

    filtered, fmeta = query_bastion_accounts(
        db_session, q="user01", page=1, page_size=25
    )
    assert len(filtered) == 1
    assert fmeta["total"] == 1

    by_org, ometa = query_bastion_accounts(
        db_session, group_name="SDIS 81", page=1, page_size=100
    )
    assert ometa["total"] == 15
    assert all((a.organization or "").startswith("SDIS") for a in by_org)
