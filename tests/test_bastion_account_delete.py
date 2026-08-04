"""Full user cleanup — delete_bastion_account (apps + Keycloak + vault/grants + fiche)."""

import pytest
import respx
from httpx import Response

from app.models import (
    AccessGrant,
    App,
    BastionAccount,
    BastionAccountProvisioning,
    RealmConfig,
    UserAppCredential,
)
from app.rbac.account_service import delete_bastion_account
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

CRUSH_ADMIN_URL = "https://crush-admin.internal:8080/"
KC_TOKEN_URL = "https://kc.example.com/realms/AR-SYSTEMS/protocol/openid-connect/token"
KC_DELETE_USER_URL = "https://kc.example.com/admin/realms/AR-SYSTEMS/users/kc-user-1"

CRUSH_OK = Response(200, text="<response>success</response>")
CRUSH_FAIL = Response(200, text="<response>failure</response>")
CRUSH_GET_USER_OK = Response(
    200,
    text='<?xml version="1.0"?><user type="properties"><username>jdoe</username><root_dir>/</root_dir></user>',
)
KC_TOKEN_OK = Response(
    200,
    json={"access_token": "tok"},
    headers={"content-type": "application/json"},
)


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
        redirect_uri="https://portal.test/cb",
        oauth2_proxy_port=4180,
        enabled=True,
        keycloak_provision_client_id="bastion-admin-provision",
        keycloak_provision_client_secret_encrypted=encrypt_secret("prov-secret", s),
        provisioning_enabled=True,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def _crushftp_app(db) -> App:
    s = _settings()
    app = App(
        slug="crushftp",
        label="CrushFTP",
        upstream_url="https://crush.public/",
        enabled=True,
        provisioning_driver="crushftp",
        crushftp_admin_base_url=CRUSH_ADMIN_URL,
        crushftp_admin_server_group="MainUsers",
        crushftp_admin_username="crushadmin",
        crushftp_admin_password_encrypted=encrypt_secret("admin-pass", s),
        crushftp_vfs_base_path="/crush_data/AR-SYSTEMS",
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def _provisioned_account(db, realm: RealmConfig, crush: App) -> BastionAccount:
    account = BastionAccount(
        realm_id=realm.id,
        username="jdoe",
        email="jdoe@example.com",
        organization="SDIS999",
        status="provisioned",
        keycloak_user_id="kc-user-1",
        origin="bastion",
        created_by="admin@example.com",
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    db.add(
        BastionAccountProvisioning(
            bastion_account_id=account.id,
            application_id=crush.id,
            driver_name="crushftp",
            status="success",
            detail="ok",
        )
    )
    db.add(
        UserAppCredential(
            app_slug=crush.slug,
            keycloak_user_id="kc-user-1",
            robotic_username="jdoe",
            encrypted_password=encrypt_secret("pw", _settings()),
        )
    )
    db.add(
        AccessGrant(
            subject_type="user",
            keycloak_user_id="kc-user-1",
            resource_type="application",
            application_id=crush.id,
            access_level="use",
            granted_by="admin@example.com",
        )
    )
    db.commit()
    db.refresh(account)
    return account


def _mock_crushftp_delete_ok():
    """getUser (exists) → setUserItem delete OK → getUser (gone)."""
    respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[CRUSH_GET_USER_OK, CRUSH_OK, CRUSH_FAIL]
    )


def _mock_keycloak_delete(status: int = 204):
    respx.post(KC_TOKEN_URL).mock(return_value=KC_TOKEN_OK)
    respx.delete(KC_DELETE_USER_URL).mock(return_value=Response(status))


@respx.mock
@pytest.mark.asyncio
async def test_delete_account_full_cleanup(db_session):
    settings = _settings()
    realm = _realm(db_session)
    crush = _crushftp_app(db_session)
    account = _provisioned_account(db_session, realm, crush)
    account_id = account.id

    _mock_crushftp_delete_ok()
    _mock_keycloak_delete(204)

    deleted, errors = await delete_bastion_account(
        db_session, settings, account=account, actor="admin@example.com"
    )
    assert deleted is True
    assert errors == []

    assert db_session.query(BastionAccount).filter_by(id=account_id).first() is None
    assert (
        db_session.query(BastionAccountProvisioning)
        .filter_by(bastion_account_id=account_id)
        .count()
        == 0
    )
    assert (
        db_session.query(UserAppCredential)
        .filter_by(keycloak_user_id="kc-user-1")
        .count()
        == 0
    )
    assert (
        db_session.query(AccessGrant)
        .filter_by(subject_type="user", keycloak_user_id="kc-user-1")
        .count()
        == 0
    )


@respx.mock
@pytest.mark.asyncio
async def test_delete_account_keycloak_404_is_idempotent(db_session):
    """User already gone in Keycloak (404) must not block the cleanup."""
    settings = _settings()
    realm = _realm(db_session)
    crush = _crushftp_app(db_session)
    account = _provisioned_account(db_session, realm, crush)
    account_id = account.id

    # CrushFTP: user already absent (getUser failure) → success "déjà absent".
    respx.post(CRUSH_ADMIN_URL).mock(return_value=CRUSH_FAIL)
    _mock_keycloak_delete(404)

    deleted, errors = await delete_bastion_account(
        db_session, settings, account=account, actor="admin@example.com"
    )
    assert deleted is True
    assert errors == []
    assert db_session.query(BastionAccount).filter_by(id=account_id).first() is None


@respx.mock
@pytest.mark.asyncio
async def test_delete_account_remote_failure_keeps_fiche(db_session):
    """Échec distant sans force → fiche conservée + last_error, retry possible."""
    settings = _settings()
    realm = _realm(db_session)
    crush = _crushftp_app(db_session)
    account = _provisioned_account(db_session, realm, crush)
    account_id = account.id

    # CrushFTP: user exists, delete responds OK but getUser still finds it.
    respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[CRUSH_GET_USER_OK, CRUSH_OK, CRUSH_GET_USER_OK]
    )
    _mock_keycloak_delete(204)

    deleted, errors = await delete_bastion_account(
        db_session, settings, account=account, actor="admin@example.com"
    )
    assert deleted is False
    assert errors and "CrushFTP" in errors[0]

    kept = db_session.query(BastionAccount).filter_by(id=account_id).first()
    assert kept is not None
    assert "Suppression incomplète" in (kept.last_error or "")
    # Vault credential and grant untouched when the fiche is kept.
    assert (
        db_session.query(UserAppCredential)
        .filter_by(keycloak_user_id="kc-user-1")
        .count()
        == 1
    )


@respx.mock
@pytest.mark.asyncio
async def test_delete_account_force_removes_fiche_despite_failure(db_session):
    settings = _settings()
    realm = _realm(db_session)
    crush = _crushftp_app(db_session)
    account = _provisioned_account(db_session, realm, crush)
    account_id = account.id

    respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[CRUSH_GET_USER_OK, CRUSH_FAIL, CRUSH_GET_USER_OK]
    )
    _mock_keycloak_delete(204)

    deleted, errors = await delete_bastion_account(
        db_session,
        settings,
        account=account,
        actor="admin@example.com",
        force=True,
    )
    assert deleted is True
    assert errors  # failure reported, deletion forced anyway
    assert db_session.query(BastionAccount).filter_by(id=account_id).first() is None
    assert (
        db_session.query(UserAppCredential)
        .filter_by(keycloak_user_id="kc-user-1")
        .count()
        == 0
    )


@respx.mock
def test_delete_route_requires_exact_username(client, db_session):
    ADMIN_HEADERS = {
        "X-Email": "admin@example.com",
        "X-Groups": "portal-admins",
        "Accept": "application/json",
    }
    realm = _realm(db_session)
    crush = _crushftp_app(db_session)
    account = _provisioned_account(db_session, realm, crush)

    resp = client.post(
        f"/admin/rbac/accounts/{account.id}/delete",
        headers=ADMIN_HEADERS,
        data={"confirm_username": "pas-le-bon"},
    )
    assert resp.status_code == 400
    assert "Confirmation invalide" in resp.json()["errors"]["confirm_username"]
    assert db_session.query(BastionAccount).filter_by(id=account.id).first() is not None


@respx.mock
def test_delete_route_full_cleanup(client, db_session):
    ADMIN_HEADERS = {
        "X-Email": "admin@example.com",
        "X-Groups": "portal-admins",
        "Accept": "application/json",
    }
    realm = _realm(db_session)
    crush = _crushftp_app(db_session)
    account = _provisioned_account(db_session, realm, crush)
    account_id = account.id

    _mock_crushftp_delete_ok()
    _mock_keycloak_delete(204)

    resp = client.post(
        f"/admin/rbac/accounts/{account_id}/delete",
        headers=ADMIN_HEADERS,
        data={"confirm_username": "jdoe"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["errors"] == []
    assert db_session.query(BastionAccount).filter_by(id=account_id).first() is None


def test_delete_button_visible_on_account_detail(client, db_session):
    ADMIN_HEADERS = {
        "X-Email": "admin@example.com",
        "X-Groups": "portal-admins",
    }
    realm = _realm(db_session)
    crush = _crushftp_app(db_session)
    account = _provisioned_account(db_session, realm, crush)

    page = client.get(f"/admin/rbac/accounts/{account.id}", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    assert "Zone dangereuse" in page.text
    assert f"/admin/rbac/accounts/{account.id}/delete" in page.text
    assert 'name="confirm_username"' in page.text
