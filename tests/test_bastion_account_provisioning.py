"""Per-app provisioning — CrushFTP driver (Basic Auth), generic no-op, aggregates."""

import base64

import pytest
import respx
from httpx import Response

from app.models import (
    App,
    BastionAccount,
    BastionAccountProvisioning,
    RealmConfig,
    UserAppCredential,
)
from app.rbac.account_service import provision_account_app, update_aggregate_status
from app.secret_crypto import decrypt_secret, encrypt_secret
from app.sso_settings import Settings

CRUSH_ADMIN_URL = "https://crush-admin.internal:8080/"

CRUSH_SET_USER_OK = Response(200, text="<response>success</response>")
CRUSH_SET_USER_FAIL = Response(200, text="<response>failure</response>")
CRUSH_AUTH_FAIL = Response(401, text="<response>failure</response>")
CRUSH_GET_USER_OK = Response(
    200,
    text='<?xml version="1.0"?><user type="properties"><username>jdoe</username><root_dir>/</root_dir></user>',
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


def _account(db, realm: RealmConfig, *, kc_id: str | None = "kc-user-1") -> BastionAccount:
    account = BastionAccount(
        realm_id=realm.id,
        username="jdoe",
        email="jdoe@example.com",
        organization="SDIS999",
        status="keycloak_created" if kc_id else "pending",
        keycloak_user_id=kc_id,
        created_by="admin@example.com",
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    return account


def _crushftp_app(db, *, with_admin_api: bool = True) -> App:
    s = _settings()
    app = App(
        slug="crushftp",
        label="CrushFTP",
        upstream_url="https://crush.public/",
        enabled=True,
        provisioning_driver="crushftp",
    )
    if with_admin_api:
        app.crushftp_admin_base_url = CRUSH_ADMIN_URL
        app.crushftp_admin_server_group = "MainUsers"
        app.crushftp_admin_username = "crushadmin"
        app.crushftp_admin_password_encrypted = encrypt_secret("admin-pass", s)
        app.crushftp_vfs_base_path = "/crush_data/AR-SYSTEMS"
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def _assert_basic_auth(request, *, username: str = "crushadmin", password: str = "admin-pass"):
    auth = request.headers.get("Authorization") or request.headers.get("authorization")
    assert auth is not None, "Expected Authorization header (Basic Auth)"
    assert auth.startswith("Basic ")
    decoded = base64.b64decode(auth.split(" ", 1)[1]).decode()
    assert decoded == f"{username}:{password}"
    cookie = request.headers.get("Cookie") or request.headers.get("cookie") or ""
    assert "CrushAuth" not in cookie
    assert "c2f" not in (request.content or b"").decode()


@respx.mock
@pytest.mark.asyncio
async def test_bastion_account_provisioning_crushftp_success(db_session):
    settings = _settings()
    realm = _realm(db_session)
    account = _account(db_session, realm)
    app = _crushftp_app(db_session)

    route = respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[
            Response(200, text="<response>failure</response>"),  # exist check
            CRUSH_SET_USER_OK,  # makedir
            CRUSH_SET_USER_OK,  # setUserItem
            CRUSH_GET_USER_OK,  # verify
            CRUSH_SET_USER_OK,  # company group
        ]
    )

    row = await provision_account_app(
        db_session, settings, account=account, app=app, actor="admin@example.com"
    )
    assert row.status == "success"
    assert row.driver_name == "crushftp"
    assert account.status == "provisioned"
    assert route.call_count == 5
    assert "FILE://crush_data/AR-SYSTEMS/SDIS999/" in (row.detail or "")

    set_user_call = route.calls[2].request.content.decode()
    _assert_basic_auth(route.calls[2].request)
    assert "setUserItem" in set_user_call
    assert "jdoe" in set_user_call
    assert "MainUsers" in set_user_call
    assert "getUser" in route.calls[3].request.content.decode()

    cred = (
        db_session.query(UserAppCredential)
        .filter_by(app_slug="crushftp", keycloak_user_id="kc-user-1")
        .first()
    )
    assert cred is not None
    assert cred.robotic_username == "jdoe"
    plaintext = decrypt_secret(cred.encrypted_password, settings)
    assert len(plaintext) >= 16
    assert plaintext not in (row.detail or "")
    assert "admin-pass" not in (row.detail or "")


@respx.mock
@pytest.mark.asyncio
async def test_bastion_account_provisioning_crushftp_api_failure(db_session):
    settings = _settings()
    realm = _realm(db_session)
    account = _account(db_session, realm)
    app = _crushftp_app(db_session)

    respx.post(CRUSH_ADMIN_URL).mock(return_value=CRUSH_SET_USER_FAIL)

    row = await provision_account_app(
        db_session, settings, account=account, app=app, actor="admin@example.com"
    )
    assert row.status == "failed"
    assert "failure" in row.detail.lower() or "échou" in row.detail.lower()
    assert "déjà existant" not in row.detail
    assert account.status == "partial_failure"
    assert (
        db_session.query(UserAppCredential).filter_by(app_slug="crushftp").count() == 0
    )


@respx.mock
@pytest.mark.asyncio
async def test_bastion_account_provisioning_crushftp_admin_login_rejected(db_session):
    settings = _settings()
    realm = _realm(db_session)
    account = _account(db_session, realm)
    app = _crushftp_app(db_session)

    route = respx.post(CRUSH_ADMIN_URL).mock(return_value=CRUSH_AUTH_FAIL)

    row = await provision_account_app(
        db_session, settings, account=account, app=app, actor="admin@example.com"
    )
    assert row.status == "failed"
    assert "admin" in row.detail.lower()
    assert "admin-pass" not in row.detail
    _assert_basic_auth(route.calls[0].request)


@pytest.mark.asyncio
async def test_bastion_account_provisioning_crushftp_missing_admin_credential(db_session):
    settings = _settings()
    realm = _realm(db_session)
    account = _account(db_session, realm)
    app = _crushftp_app(db_session, with_admin_api=False)

    row = await provision_account_app(
        db_session, settings, account=account, app=app, actor="admin@example.com"
    )
    assert row.status == "failed"
    assert "api admin" in row.detail.lower()
    assert "non configurée" in row.detail.lower() or "renseignez" in row.detail.lower()


@pytest.mark.asyncio
async def test_bastion_account_provisioning_generic_not_applicable(db_session):
    settings = _settings()
    realm = _realm(db_session)
    account = _account(db_session, realm)
    app = App(
        slug="wikijs",
        label="Wiki.js",
        upstream_url="https://wiki.internal/",
        enabled=True,
        provisioning_driver="generic",
    )
    db_session.add(app)
    db_session.commit()

    row = await provision_account_app(
        db_session, settings, account=account, app=app, actor="admin@example.com"
    )
    assert row.status == "not_applicable"
    assert "SSO complet" in row.detail
    assert account.status == "provisioned"


@pytest.mark.asyncio
async def test_bastion_account_provisioning_no_driver_not_applicable(db_session):
    settings = _settings()
    realm = _realm(db_session)
    account = _account(db_session, realm)
    app = App(
        slug="grafana",
        label="Grafana",
        upstream_url="https://grafana.internal/",
        enabled=True,
        provisioning_driver=None,
    )
    db_session.add(app)
    db_session.commit()

    row = await provision_account_app(
        db_session, settings, account=account, app=app, actor="admin@example.com"
    )
    assert row.status == "not_applicable"
    assert "Aucun driver" in row.detail


@pytest.mark.asyncio
async def test_bastion_account_provisioning_requires_keycloak_user(db_session):
    """Never provision an app for an account whose Keycloak step failed."""
    settings = _settings()
    realm = _realm(db_session)
    account = _account(db_session, realm, kc_id=None)
    app = _crushftp_app(db_session)

    row = await provision_account_app(
        db_session, settings, account=account, app=app, actor="admin@example.com"
    )
    assert row.status == "failed"
    assert "Keycloak" in row.detail
    assert account.status == "pending"


@respx.mock
@pytest.mark.asyncio
async def test_bastion_account_provisioning_aggregate_never_masks_failure(db_session):
    """success + failed → partial_failure, jamais 'provisioned'."""
    settings = _settings()
    realm = _realm(db_session)
    account = _account(db_session, realm)
    crush = _crushftp_app(db_session)
    sso_app = App(
        slug="wikijs",
        label="Wiki.js",
        upstream_url="https://wiki.internal/",
        enabled=True,
        provisioning_driver="generic",
    )
    db_session.add(sso_app)
    db_session.commit()

    respx.post(CRUSH_ADMIN_URL).mock(return_value=CRUSH_SET_USER_FAIL)

    ok_row = await provision_account_app(
        db_session, settings, account=account, app=sso_app, actor="admin@example.com"
    )
    failed_row = await provision_account_app(
        db_session, settings, account=account, app=crush, actor="admin@example.com"
    )
    assert ok_row.status == "not_applicable"
    assert failed_row.status == "failed"
    assert account.status == "partial_failure"

    rows = db_session.query(BastionAccountProvisioning).filter_by(
        bastion_account_id=account.id
    )
    assert rows.count() == 2

    update_aggregate_status(account)
    assert account.status == "partial_failure"


@respx.mock
def test_provision_selected_apps_from_account_detail(client, db_session):
    """POST /provision avec application_ids cochées lance le driver."""
    ADMIN_HEADERS = {
        "X-Email": "admin@example.com",
        "X-Groups": "portal-admins",
    }
    JSON_HEADERS = {**ADMIN_HEADERS, "Accept": "application/json"}

    realm = _realm(db_session)
    crush = _crushftp_app(db_session)
    account = BastionAccount(
        realm_id=realm.id,
        username="toto",
        email="toto@example.com",
        organization="SDIS999",
        status="keycloak_created",
        keycloak_user_id="kc-toto",
        origin="bastion",
        created_by="admin@example.com",
    )
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)

    page = client.get(f"/admin/rbac/accounts/{account.id}", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    assert "Lancer le provisioning" in page.text
    assert 'name="application_ids"' in page.text
    assert crush.label in page.text

    respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[
            Response(200, text="<response>failure</response>"),
            CRUSH_SET_USER_OK,
            CRUSH_SET_USER_OK,
            Response(
                200,
                text='<?xml version="1.0"?><user type="properties"><username>toto</username><root_dir>/</root_dir></user>',
            ),
            CRUSH_SET_USER_OK,
        ]
    )
    resp = client.post(
        f"/admin/rbac/accounts/{account.id}/provision",
        headers=JSON_HEADERS,
        data={"application_ids": str(crush.id)},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["retried"] == 1

    row = (
        db_session.query(BastionAccountProvisioning)
        .filter_by(bastion_account_id=account.id, application_id=crush.id)
        .first()
    )
    assert row is not None
    assert row.status == "success"


@respx.mock
def test_provision_retry_all_failed_and_pending(client, db_session):
    """Relancer les échecs / en attente via POST provision-retry-all."""
    ADMIN_HEADERS = {
        "X-Email": "admin@example.com",
        "X-Groups": "portal-admins",
    }
    JSON_HEADERS = {**ADMIN_HEADERS, "Accept": "application/json"}

    realm = _realm(db_session)
    crush = _crushftp_app(db_session)
    pending_app = App(
        slug="generic-app",
        label="Generic App",
        upstream_url="https://app.internal/",
        enabled=True,
        provisioning_driver="generic",
    )
    db_session.add(pending_app)
    db_session.commit()
    db_session.refresh(pending_app)

    account = BastionAccount(
        realm_id=realm.id,
        username="jdoe",
        email="jdoe@example.com",
        organization="SDIS999",
        status="partial_failure",
        keycloak_user_id="kc-user-1",
        origin="bastion",
        created_by="admin@example.com",
        pending_application_ids=[pending_app.id],
    )
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)

    failed_row = BastionAccountProvisioning(
        bastion_account_id=account.id,
        application_id=crush.id,
        driver_name="crushftp",
        status="failed",
        detail="previous failure",
    )
    db_session.add(failed_row)
    db_session.commit()

    respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[
            Response(200, text="<response>failure</response>"),
            CRUSH_SET_USER_OK,
            CRUSH_SET_USER_OK,
            CRUSH_GET_USER_OK,
            CRUSH_SET_USER_OK,
        ]
    )

    resp = client.post(
        f"/admin/rbac/accounts/{account.id}/provision-retry-all",
        headers=JSON_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["retried"] == 2
    assert body["failures"] == 0

    db_session.refresh(account)
    rows = {
        r.application_id: r.status
        for r in db_session.query(BastionAccountProvisioning)
        .filter_by(bastion_account_id=account.id)
        .all()
    }
    assert rows[crush.id] == "success"
    assert rows[pending_app.id] == "not_applicable"

    detail = client.get(f"/admin/rbac/accounts/{account.id}", headers=ADMIN_HEADERS)
    assert detail.status_code == 200
    assert "Provisioning applicatif" in detail.text
    assert "Lancer le provisioning" in detail.text
