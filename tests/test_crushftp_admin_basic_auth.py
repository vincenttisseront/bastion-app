"""CrushFTP Admin API — HTTP Basic Auth (Étape 1.2 / §13)."""

import base64
import logging
from urllib.parse import parse_qs

import pytest
import respx
from httpx import Response

from app.bastion.drivers.base_provisioning import GeneratedCredential
from app.bastion.drivers.crushftp import CrushFTPProvisioningDriver
from app.models import App
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

CRUSH_ADMIN_URL = "http://10.0.0.50:8080/"
ADMIN_PASS = "s3cret-admin-pass"


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )


def _app(db, *, server_group: str | None = "MainUsers") -> App:
    s = _settings()
    app = App(
        slug="transfer",
        label="Transfer",
        upstream_url="https://transfer.public/",
        enabled=True,
        provisioning_driver="crushftp",
        crushftp_admin_base_url=CRUSH_ADMIN_URL,
        crushftp_admin_server_group=server_group,
        crushftp_admin_username="crushadmin",
        crushftp_admin_password_encrypted=encrypt_secret(ADMIN_PASS, s),
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def _basic_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def _assert_basic_auth_only(request):
    auth = request.headers.get("Authorization") or request.headers.get("authorization")
    assert auth == _basic_header("crushadmin", ADMIN_PASS)
    cookie = request.headers.get("Cookie") or request.headers.get("cookie") or ""
    assert "CrushAuth" not in cookie
    assert "currentAuth" not in cookie
    body = (request.content or b"").decode()
    assert "c2f=" not in body
    assert "command=login" not in body


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_admin_basic_auth_create_account(db_session, caplog):
    settings = _settings()
    app = _app(db_session)
    route = respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[
            Response(200, text="<response>success</response>"),
            Response(
                200,
                text='<?xml version="1.0"?><user type="properties"><username>jdoe</username><root_dir>/</root_dir></user>',
            ),
        ]
    )
    driver = CrushFTPProvisioningDriver()
    cred = GeneratedCredential(username="jdoe", password="user-pass-16chars")

    with caplog.at_level(logging.DEBUG):
        result = await driver.create_account(
            db=db_session,
            settings=settings,
            app=app,
            account=None,
            credential=cred,
        )

    assert result.status == "success"
    assert "jdoe" in result.detail
    assert route.call_count == 2
    req = route.calls[0].request
    _assert_basic_auth_only(req)
    form = parse_qs(req.content.decode())
    assert form["command"] == ["setUserItem"]
    assert form["xmlItem"] == ["user"]
    assert form["data_action"] == ["replace"]
    assert form["serverGroup"] == ["MainUsers"]
    assert form["username"] == ["jdoe"]
    assert "vfs_items" in form and "vfs_items type=" in form["vfs_items"][0]
    assert "FILE://users/jdoe/" in form["vfs_items"][0]
    assert "permissions" in form and "<VFS" in form["permissions"][0]
    perms = form["permissions"][0]
    assert "(read)(view)(resume)" in perms
    assert "(write)" not in perms
    assert "(delete)" not in perms
    assert "(makedir)" not in perms
    assert route.calls[1].request.content.decode().find("getUser") >= 0

    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert ADMIN_PASS not in joined
    assert "s3cret" not in joined
    assert _basic_header("crushadmin", ADMIN_PASS) not in joined


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_admin_create_fails_when_getuser_missing(db_session):
    settings = _settings()
    app = _app(db_session)
    respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[
            Response(200, text="<response>success</response>"),
            Response(200, text="<response>failure</response>"),
        ]
    )
    driver = CrushFTPProvisioningDriver()
    result = await driver.create_account(
        db=db_session,
        settings=settings,
        app=app,
        account=None,
        credential=GeneratedCredential(username="toto", password="user-pass-16chars"),
    )
    assert result.status == "failed"
    assert "getUser" in result.detail
    assert "toto" in result.detail


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_admin_accepts_response_status_ok(db_session):
    settings = _settings()
    app = _app(db_session)
    respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[
            Response(200, text="<response_status>OK</response_status>"),
            Response(
                200,
                text="<user type=\"properties\"><username>toto</username><root_dir>/</root_dir></user>",
            ),
        ]
    )
    driver = CrushFTPProvisioningDriver()
    result = await driver.create_account(
        db=db_session,
        settings=settings,
        app=app,
        account=None,
        credential=GeneratedCredential(username="toto", password="user-pass-16chars"),
    )
    assert result.status == "success"


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_admin_failure_body_not_already_exists(db_session):
    settings = _settings()
    app = _app(db_session)
    respx.post(CRUSH_ADMIN_URL).respond(200, text="<response>failure</response>")
    driver = CrushFTPProvisioningDriver()
    result = await driver.create_account(
        db=db_session,
        settings=settings,
        app=app,
        account=None,
        credential=GeneratedCredential(username="toto", password="user-pass-16chars"),
    )
    assert result.status == "failed"
    assert "failure" in result.detail.lower()
    assert "déjà existant" not in result.detail


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_admin_api_redirect_hints_public_sso_url(db_session):
    """302 from bastion/SSO URL must not look like « compte déjà existant »."""
    settings = _settings()
    app = _app(db_session)
    respx.post(CRUSH_ADMIN_URL).respond(
        302, headers={"Location": "https://portal.example/oauth2/start"}
    )
    driver = CrushFTPProvisioningDriver()
    result = await driver.create_account(
        db=db_session,
        settings=settings,
        app=app,
        account=None,
        credential=GeneratedCredential(username="toto", password="user-pass-16chars"),
    )
    assert result.status == "failed"
    assert "302" in result.detail
    assert "SSO" in result.detail or "bastion" in result.detail.lower()
    assert "déjà existant" not in result.detail


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_admin_basic_auth_add_user_to_group(db_session):
    settings = _settings()
    app = _app(db_session, server_group="CustomUsers")
    route = respx.post(CRUSH_ADMIN_URL).respond(
        200, text="<response>success</response>"
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
    assert route.call_count == 1
    req = route.calls[0].request
    _assert_basic_auth_only(req)
    form = parse_qs(req.content.decode())
    assert form["xmlItem"] == ["groups"]
    assert form["data_action"] == ["add"]
    assert form["serverGroup"] == ["CustomUsers"]
    assert form["group_name"] == ["ARSYSTEMS-Users"]
    assert form["usernames"] == ["jdoe"]


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_admin_basic_auth_remove_user_from_group(db_session):
    settings = _settings()
    app = _app(db_session)
    route = respx.post(CRUSH_ADMIN_URL).respond(
        200, text="<response>success</response>"
    )
    driver = CrushFTPProvisioningDriver()

    result = await driver.remove_user_from_group(
        db=db_session,
        settings=settings,
        app=app,
        username="jdoe",
        group_name="ARSYSTEMS-Users",
    )
    assert result.status == "success"
    assert route.call_count == 1
    req = route.calls[0].request
    _assert_basic_auth_only(req)
    form = parse_qs(req.content.decode())
    assert form["xmlItem"] == ["groups"]
    assert form["data_action"] == ["delete"]


@respx.mock
@pytest.mark.asyncio
async def test_crushftp_admin_basic_auth_default_server_group_when_empty(db_session):
    settings = _settings()
    app = _app(db_session, server_group="")
    app.crushftp_admin_server_group = None
    db_session.commit()

    route = respx.post(CRUSH_ADMIN_URL).respond(
        200, text="<response>success</response>"
    )
    driver = CrushFTPProvisioningDriver()
    await driver.add_user_to_group(
        db=db_session,
        settings=settings,
        app=app,
        username="jdoe",
        group_name="G1",
    )
    form = parse_qs(route.calls[0].request.content.decode())
    assert form["serverGroup"] == ["MainUsers"]
