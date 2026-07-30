"""CrushFTP group membership via setUserItem xmlItem=groups (Étape 1.1)."""

import pytest
import respx
from httpx import Response
from urllib.parse import parse_qs

from app.models import App, AppCredential, BastionAccount, RealmConfig
from app.rbac.account_service import provision_account_app
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

CRUSH_URL = "https://crush.internal/WebInterface/function/"

CRUSH_LOGIN_OK = Response(
    200,
    text="<response>success</response>",
    headers=[("set-cookie", "CrushAuth=1234567890abcd; Path=/")],
)
CRUSH_OK = Response(200, text="<response>success</response>")
CRUSH_FAIL = Response(200, text="<response>failure</response>")
CRUSH_LOGOUT_OK = Response(200, text="<response>success</response>")


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )


def _seed(db):
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
    app = App(
        slug="crushftp",
        label="CrushFTP",
        upstream_url="https://crush.internal/",
        enabled=True,
        provisioning_driver="crushftp",
    )
    db.add_all([realm, app])
    db.commit()
    db.refresh(realm)
    db.refresh(app)
    db.add(
        AppCredential(
            app_slug=app.slug,
            robotic_username="crushadmin",
            encrypted_password=encrypt_secret("admin-pass", s),
            is_active=True,
        )
    )
    account = BastionAccount(
        realm_id=realm.id,
        username="jdoe",
        email="jdoe@example.com",
        status="keycloak_created",
        keycloak_user_id="kc-user-1",
        created_by="admin@example.com",
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    return realm, app, account


def _form(content: bytes) -> dict[str, list[str]]:
    return parse_qs(content.decode())


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_group_add_success_same_admin_session(db_session):
    """login → create user → add group → logout — one session, no second login."""
    settings = _settings()
    _, app, account = _seed(db_session)

    route = respx.post(CRUSH_URL).mock(
        side_effect=[CRUSH_LOGIN_OK, CRUSH_OK, CRUSH_OK, CRUSH_LOGOUT_OK]
    )

    row = await provision_account_app(
        db_session,
        settings,
        account=account,
        app=app,
        actor="admin@example.com",
        group_names=["ARSYSTEMS-Users"],
    )
    assert row.status == "success"
    assert "Compte CrushFTP créé" in row.detail
    assert "ARSYSTEMS-Users=ok" in row.detail
    assert route.call_count == 4  # login + user + group + logout

    user_form = _form(route.calls[1].request.content)
    assert user_form["xmlItem"] == ["user"]
    assert user_form["username"] == ["jdoe"]

    group_form = _form(route.calls[2].request.content)
    assert group_form["command"] == ["setUserItem"]
    assert group_form["xmlItem"] == ["groups"]
    assert group_form["data_action"] == ["add"]
    assert group_form["group_name"] == ["ARSYSTEMS-Users"]
    assert group_form["usernames"] == ["jdoe"]
    # Never leak secrets into detail
    assert "admin-pass" not in (row.detail or "")


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_group_failure_keeps_user_success(db_session):
    """User create OK + group API fail → status stays success; both visible in detail."""
    settings = _settings()
    _, app, account = _seed(db_session)

    respx.post(CRUSH_URL).mock(
        side_effect=[CRUSH_LOGIN_OK, CRUSH_OK, CRUSH_FAIL, CRUSH_LOGOUT_OK]
    )

    row = await provision_account_app(
        db_session,
        settings,
        account=account,
        app=app,
        actor="admin@example.com",
        group_names=["Missing-Group"],
    )
    assert row.status == "success"  # user create not masked by group failure
    assert "Compte CrushFTP créé" in row.detail
    assert "Missing-Group=échec" in row.detail
    assert account.status == "provisioned"


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_group_implicit_create_same_call(db_session):
    """CrushFTP creates the group on first add — no separate create_group call."""
    settings = _settings()
    _, app, account = _seed(db_session)

    route = respx.post(CRUSH_URL).mock(
        side_effect=[CRUSH_LOGIN_OK, CRUSH_OK, CRUSH_OK, CRUSH_LOGOUT_OK]
    )

    row = await provision_account_app(
        db_session,
        settings,
        account=account,
        app=app,
        actor="admin@example.com",
        group_names=["Brand-New-Group"],
    )
    assert row.status == "success"
    assert "Brand-New-Group=ok" in row.detail
    # Exactly one groups call (add creates implicitly) — never a distinct "create group".
    group_calls = [
        c for c in route.calls if b"xmlItem=groups" in (c.request.content or b"")
    ]
    assert len(group_calls) == 1


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_no_group_names_skips_group_call(db_session):
    """Non-régression: without group_names, behaviour identical to V1 (no groups call)."""
    settings = _settings()
    _, app, account = _seed(db_session)

    route = respx.post(CRUSH_URL).mock(
        side_effect=[CRUSH_LOGIN_OK, CRUSH_OK, CRUSH_LOGOUT_OK]
    )

    row = await provision_account_app(
        db_session,
        settings,
        account=account,
        app=app,
        actor="admin@example.com",
        group_names=None,
    )
    assert row.status == "success"
    assert "Groupes:" not in (row.detail or "")
    assert route.call_count == 3
    assert not any(b"xmlItem=groups" in (c.request.content or b"") for c in route.calls)


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_empty_group_names_skips_group_call(db_session):
    settings = _settings()
    _, app, account = _seed(db_session)

    route = respx.post(CRUSH_URL).mock(
        side_effect=[CRUSH_LOGIN_OK, CRUSH_OK, CRUSH_LOGOUT_OK]
    )

    row = await provision_account_app(
        db_session,
        settings,
        account=account,
        app=app,
        actor="admin@example.com",
        group_names=[],
    )
    assert row.status == "success"
    assert route.call_count == 3
    assert not any(b"xmlItem=groups" in (c.request.content or b"") for c in route.calls)


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_add_user_to_group_standalone(db_session):
    settings = _settings()
    _, app, _ = _seed(db_session)
    from app.bastion.drivers.crushftp import CrushFTPProvisioningDriver

    route = respx.post(CRUSH_URL).mock(
        side_effect=[CRUSH_LOGIN_OK, CRUSH_OK, CRUSH_LOGOUT_OK]
    )
    driver = CrushFTPProvisioningDriver()
    result = await driver.add_user_to_group(
        db=db_session,
        settings=settings,
        app=app,
        username="jdoe",
        group_name="ARSYSTEMS-Users",
    )
    assert result.status == "success"
    assert "ARSYSTEMS-Users" in result.detail
    group_form = _form(route.calls[1].request.content)
    assert group_form["xmlItem"] == ["groups"]
    assert group_form["data_action"] == ["add"]
