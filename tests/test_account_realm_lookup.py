"""Coverage for Bastion account realm lookup helpers."""

from __future__ import annotations

from app.models import BastionAccount, RealmConfig
from app.rbac.account_service import _bastion_account_in_realm
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
    )


def _realm(db, *, slug: str = "default") -> RealmConfig:
    settings = _settings()
    realm = RealmConfig(
        slug=slug,
        name=slug.title(),
        enabled=True,
        issuer_url=f"https://idp.example.com/realms/{slug}",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", settings),
        redirect_uri=f"https://portal.example.com/oauth2/{slug}/callback",
        oauth2_proxy_port=4180,
        is_default=True,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def test_bastion_account_in_realm_by_username(db_session):
    realm = _realm(db_session)
    source = BastionAccount(
        realm_id=realm.id,
        username="alice",
        email="alice@example.com",
        status="keycloak_created",
        origin="bastion",
        created_by="admin@example.com",
        keycloak_user_id="kc-alice",
    )
    db_session.add(source)
    db_session.commit()

    found = _bastion_account_in_realm(
        db_session, realm_id=realm.id, source_account=source
    )
    assert found is not None
    assert found.keycloak_user_id == "kc-alice"


def test_bastion_account_in_realm_falls_back_to_email(db_session):
    realm = _realm(db_session)
    source = BastionAccount(
        realm_id=realm.id,
        username="alice-local",
        email="alice@example.com",
        status="pending",
        origin="bastion",
        created_by="admin@example.com",
        keycloak_user_id=None,
    )
    sibling = BastionAccount(
        realm_id=realm.id,
        username="alice",
        email="alice@example.com",
        status="keycloak_created",
        origin="bastion",
        created_by="admin@example.com",
        keycloak_user_id="kc-alice",
    )
    db_session.add_all([source, sibling])
    db_session.commit()

    found = _bastion_account_in_realm(
        db_session, realm_id=realm.id, source_account=source
    )
    assert found is not None
    assert found.username == "alice"
    assert found.keycloak_user_id == "kc-alice"


def test_bastion_account_in_realm_no_email_returns_username_row(db_session):
    realm = _realm(db_session)
    source = BastionAccount(
        realm_id=realm.id,
        username="bob",
        email="",
        status="pending",
        origin="bastion",
        created_by="admin@example.com",
        keycloak_user_id=None,
    )
    db_session.add(source)
    db_session.commit()
    found = _bastion_account_in_realm(
        db_session, realm_id=realm.id, source_account=source
    )
    assert found is source
