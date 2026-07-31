"""CrushFTP group membership via setUserItem xmlItem=groups (Basic Auth)."""

import base64
from urllib.parse import parse_qs

import pytest
import respx
from httpx import Response

from app.models import App, BastionAccount, RealmConfig
from app.rbac.account_service import provision_account_app
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

CRUSH_ADMIN_URL = "https://crush-admin.internal:8080/"

CRUSH_OK = Response(200, text="<response>success</response>")
CRUSH_FAIL = Response(200, text="<response>failure</response>")
CRUSH_GET_USER = Response(
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
        upstream_url="https://crush.public/",
        enabled=True,
        provisioning_driver="crushftp",
        crushftp_admin_base_url=CRUSH_ADMIN_URL,
        crushftp_admin_server_group="MainUsers",
        crushftp_admin_username="crushadmin",
        crushftp_admin_password_encrypted=encrypt_secret("admin-pass", s),
        crushftp_vfs_base_path="/crush_data/AR-SYSTEMS",
    )
    db.add_all([realm, app])
    db.commit()
    db.refresh(realm)
    db.refresh(app)
    account = BastionAccount(
        realm_id=realm.id,
        username="jdoe",
        email="jdoe@example.com",
        organization="SDIS999",
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


def _assert_basic_auth(request):
    auth = request.headers.get("Authorization") or request.headers.get("authorization")
    assert auth is not None and auth.startswith("Basic ")
    decoded = base64.b64decode(auth.split(" ", 1)[1]).decode()
    assert decoded == "crushadmin:admin-pass"
    cookie = request.headers.get("Cookie") or request.headers.get("cookie") or ""
    assert "CrushAuth" not in cookie


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_group_add_success_same_admin_session(db_session):
    """create user + add group — Basic Auth per request, no CrushAuth session."""
    settings = _settings()
    _, app, account = _seed(db_session)

    route = respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[
            CRUSH_FAIL,  # exist
            CRUSH_OK,  # makedir
            CRUSH_OK,  # setUserItem user
            CRUSH_GET_USER,
            CRUSH_OK,  # group SDIS999
            CRUSH_OK,  # group ARSYSTEMS-Users
        ]
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
    assert "SDIS999=ok" in row.detail
    assert route.call_count == 6

    for call in route.calls:
        _assert_basic_auth(call.request)

    user_form = _form(route.calls[2].request.content)
    assert user_form["xmlItem"] == ["user"]
    assert user_form["username"] == ["jdoe"]
    assert user_form["serverGroup"] == ["MainUsers"]
    assert "FILE://crush_data/AR-SYSTEMS/SDIS999/" in user_form["vfs_items"][0]

    assert b"getUser" in (route.calls[3].request.content or b"")

    group_forms = [_form(route.calls[i].request.content) for i in (4, 5)]
    assert {g["group_name"][0] for g in group_forms} == {"SDIS999", "ARSYSTEMS-Users"}
    assert "admin-pass" not in (row.detail or "")


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_group_failure_keeps_user_success(db_session):
    """User create OK + group API fail → status stays success; both visible in detail."""
    settings = _settings()
    _, app, account = _seed(db_session)

    respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[
            CRUSH_FAIL,
            CRUSH_OK,
            CRUSH_OK,
            CRUSH_GET_USER,
            CRUSH_OK,  # SDIS999
            CRUSH_FAIL,  # Missing-Group
        ]
    )

    row = await provision_account_app(
        db_session,
        settings,
        account=account,
        app=app,
        actor="admin@example.com",
        group_names=["Missing-Group"],
    )
    assert row.status == "success"
    assert "Compte CrushFTP créé" in row.detail
    assert "Missing-Group=échec" in row.detail
    assert account.status == "provisioned"


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_group_implicit_create_same_call(db_session):
    """CrushFTP creates the group on first add — no separate create_group call."""
    settings = _settings()
    _, app, account = _seed(db_session)

    route = respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[
            CRUSH_FAIL,
            CRUSH_OK,
            CRUSH_OK,
            CRUSH_GET_USER,
            CRUSH_OK,
            CRUSH_OK,
        ]
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
    group_calls = [
        c for c in route.calls if b"xmlItem=groups" in (c.request.content or b"")
    ]
    assert len(group_calls) == 2  # société + Brand-New-Group


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_always_adds_company_group(db_session):
    """Même sans group_names explicites — groupe société monté + ajouté."""
    settings = _settings()
    _, app, account = _seed(db_session)

    route = respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[CRUSH_FAIL, CRUSH_OK, CRUSH_OK, CRUSH_GET_USER, CRUSH_OK]
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
    assert "SDIS999=ok" in (row.detail or "")
    assert route.call_count == 5
    group_calls = [
        c for c in route.calls if b"xmlItem=groups" in (c.request.content or b"")
    ]
    assert len(group_calls) == 1
    assert _form(group_calls[0].request.content)["group_name"] == ["SDIS999"]


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_empty_group_names_still_adds_company(db_session):
    settings = _settings()
    _, app, account = _seed(db_session)

    route = respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[CRUSH_FAIL, CRUSH_OK, CRUSH_OK, CRUSH_GET_USER, CRUSH_OK]
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
    assert route.call_count == 5
    assert any(b"group_name=SDIS999" in (c.request.content or b"") for c in route.calls)


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_add_user_to_group_standalone(db_session):
    settings = _settings()
    _, app, _ = _seed(db_session)
    from app.bastion.drivers.crushftp import CrushFTPProvisioningDriver

    route = respx.post(CRUSH_ADMIN_URL).mock(return_value=CRUSH_OK)
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
    assert route.call_count == 1
    _assert_basic_auth(route.calls[0].request)
    group_form = _form(route.calls[0].request.content)
    assert group_form["xmlItem"] == ["groups"]
    assert group_form["data_action"] == ["add"]
