"""Per-app provisioning — CrushFTP driver (mocked), generic no-op, aggregates."""

import pytest
import respx
from httpx import Response

from app.models import (
    App,
    AppCredential,
    BastionAccount,
    BastionAccountProvisioning,
    RealmConfig,
    UserAppCredential,
)
from app.rbac.account_service import provision_account_app, update_aggregate_status
from app.secret_crypto import decrypt_secret, encrypt_secret
from app.sso_settings import Settings

CRUSH_URL = "https://crush.internal/WebInterface/function/"

CRUSH_LOGIN_OK = Response(
    200,
    text="<response>success</response>",
    headers=[("set-cookie", "CrushAuth=1234567890abcd; Path=/")],
)
CRUSH_SET_USER_OK = Response(200, text="<response>success</response>")
CRUSH_SET_USER_FAIL = Response(200, text="<response>failure</response>")
CRUSH_LOGOUT_OK = Response(200, text="<response>success</response>")


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
        status="keycloak_created" if kc_id else "pending",
        keycloak_user_id=kc_id,
        created_by="admin@example.com",
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    return account


def _crushftp_app(db, *, with_admin_credential: bool = True) -> App:
    app = App(
        slug="crushftp",
        label="CrushFTP",
        upstream_url="https://crush.internal/",
        enabled=True,
        provisioning_driver="crushftp",
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    if with_admin_credential:
        db.add(
            AppCredential(
                app_slug=app.slug,
                robotic_username="crushadmin",
                encrypted_password=encrypt_secret("admin-pass", _settings()),
                is_active=True,
            )
        )
        db.commit()
    return app


@respx.mock
@pytest.mark.asyncio
async def test_bastion_account_provisioning_crushftp_success(db_session):
    settings = _settings()
    realm = _realm(db_session)
    account = _account(db_session, realm)
    app = _crushftp_app(db_session)

    route = respx.post(CRUSH_URL).mock(
        side_effect=[CRUSH_LOGIN_OK, CRUSH_SET_USER_OK, CRUSH_LOGOUT_OK]
    )

    row = await provision_account_app(
        db_session, settings, account=account, app=app, actor="admin@example.com"
    )
    assert row.status == "success"
    assert row.driver_name == "crushftp"
    assert account.status == "provisioned"
    assert route.call_count == 3  # admin login + setUserItem + logout

    # setUserItem payload uses the generated credential for the target user.
    set_user_call = route.calls[1].request.content.decode()
    assert "setUserItem" in set_user_call
    assert "jdoe" in set_user_call

    # Credential stored encrypted in the internal vault — never in `detail`.
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

    respx.post(CRUSH_URL).mock(
        side_effect=[CRUSH_LOGIN_OK, CRUSH_SET_USER_FAIL, CRUSH_LOGOUT_OK]
    )

    row = await provision_account_app(
        db_session, settings, account=account, app=app, actor="admin@example.com"
    )
    assert row.status == "failed"
    assert "rejeté" in row.detail
    assert account.status == "partial_failure"  # never a masked aggregate
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

    respx.post(CRUSH_URL).respond(200, text="<response>failure</response>")

    row = await provision_account_app(
        db_session, settings, account=account, app=app, actor="admin@example.com"
    )
    assert row.status == "failed"
    assert "admin" in row.detail.lower()
    assert "admin-pass" not in row.detail


@pytest.mark.asyncio
async def test_bastion_account_provisioning_crushftp_missing_admin_credential(db_session):
    settings = _settings()
    realm = _realm(db_session)
    account = _account(db_session, realm)
    app = _crushftp_app(db_session, with_admin_credential=False)

    row = await provision_account_app(
        db_session, settings, account=account, app=app, actor="admin@example.com"
    )
    assert row.status == "failed"
    assert "vault" in row.detail.lower()


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
    assert account.status == "provisioned"  # not_applicable counts as ok


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

    respx.post(CRUSH_URL).mock(
        side_effect=[CRUSH_LOGIN_OK, CRUSH_SET_USER_FAIL, CRUSH_LOGOUT_OK]
    )

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
