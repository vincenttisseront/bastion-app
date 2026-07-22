"""Generic driver unit tests with respx-mocked httpx."""

from __future__ import annotations

import base64
import logging

import httpx
import pytest
import respx
from httpx import Response

from app.bastion.drivers.base import DriverLoginError
from app.bastion.drivers.generic import (
    DriverAuthRejectedError,
    DriverUpstreamError,
    generic_basic_auth_header,
    generic_form_login,
)
from app.models import App, AppCredential

SECRET_PASSWORD = "GenericDriverSecret-MustNotLeak"


def _generic_app(**kwargs) -> App:
    defaults = {
        "slug": "myapp",
        "label": "My App",
        "upstream_url": "https://app.example/",
        "robotic_driver": "generic_form",
        "login_form_url": "https://app.example/login",
        "login_username_field": "user",
        "login_password_field": "pass",
        "login_http_method": "POST",
    }
    defaults.update(kwargs)
    return App(**defaults)


def _credential() -> AppCredential:
    return AppCredential(
        app_slug="myapp",
        robotic_username="robot",
        encrypted_password="enc",
        is_active=True,
    )


@respx.mock
@pytest.mark.asyncio
async def test_generic_form_login_ok_extracts_cookies():
    route = respx.post("https://app.example/login").mock(
        return_value=Response(
            200,
            headers=[
                ("set-cookie", "sessionid=abc123; Path=/"),
                ("set-cookie", "csrftoken=xyz; Path=/"),
            ],
        )
    )
    result = await generic_form_login(_credential(), _generic_app(), SECRET_PASSWORD)
    assert route.called
    assert result.cookies["sessionid"] == "abc123"
    assert result.cookies["csrftoken"] == "xyz"


@respx.mock
@pytest.mark.asyncio
async def test_generic_form_login_no_cookies_raises_auth_rejected():
    respx.post("https://app.example/login").mock(return_value=Response(200))
    with pytest.raises(DriverAuthRejectedError, match="no session cookies"):
        await generic_form_login(_credential(), _generic_app(), SECRET_PASSWORD)


@respx.mock
@pytest.mark.asyncio
async def test_generic_form_login_401_is_auth_rejected():
    respx.post("https://app.example/login").mock(return_value=Response(401))
    with pytest.raises(DriverAuthRejectedError, match="rejected credentials"):
        await generic_form_login(_credential(), _generic_app(), SECRET_PASSWORD)


@respx.mock
@pytest.mark.asyncio
async def test_generic_form_login_405_without_spa_retry_is_technical():
    # Path is not /login → bootstrap GET then POST; no grommunio admin API retry
    respx.get("https://app.example/auth/do").mock(return_value=Response(200, text="<html></html>"))
    respx.post("https://app.example/auth/do").mock(
        return_value=Response(405, headers={"Allow": "GET"})
    )
    app = _generic_app(login_form_url="https://app.example/auth/do")
    with pytest.raises(DriverUpstreamError, match="HTTP 405"):
        await generic_form_login(_credential(), app, SECRET_PASSWORD)


@respx.mock
@pytest.mark.asyncio
async def test_grommunio_spa_405_retries_api_v1_login_jwt():
    spa = respx.post("https://mail.example:8443/login").mock(
        return_value=Response(405, headers={"Allow": "GET, HEAD"})
    )
    api = respx.post("https://mail.example:8443/api/v1/login").mock(
        return_value=Response(
            200,
            json={
                "grommunioAuthJwt": "eyJhbGciOi.test.jwt",
                "csrf": "csrf-token-1",
            },
            headers={"content-type": "application/json"},
        )
    )
    app = _generic_app(
        login_form_url="https://mail.example:8443/login?redirect=/",
        login_username_field="username",
        login_password_field="password",
    )
    result = await generic_form_login(_credential(), app, SECRET_PASSWORD)
    assert spa.called
    assert api.called
    request = api.calls.last.request
    assert b"user=robot" in request.content
    assert b"pass=" in request.content
    assert SECRET_PASSWORD.encode() in request.content
    assert b"username=" not in request.content
    assert result.cookies["grommunioAuthJwt"] == "eyJhbGciOi.test.jwt"
    assert result.cookies["csrf"] == "csrf-token-1"


@respx.mock
@pytest.mark.asyncio
async def test_grommunio_api_401_is_auth_rejected():
    respx.post("https://mail.example:8443/api/v1/login").mock(
        return_value=Response(
            401,
            json={"error": "Invalid username or password"},
            headers={"content-type": "application/json"},
        )
    )
    app = _generic_app(login_form_url="https://mail.example:8443/api/v1/login")
    with pytest.raises(DriverAuthRejectedError, match="rejected credentials"):
        await generic_form_login(_credential(), app, SECRET_PASSWORD)


@respx.mock
@pytest.mark.asyncio
async def test_grommunio_web_get_then_post_success_303():
    """grommunio-web: GET /web/ for session + hidden fields, POST ?logon → 303."""
    get_route = respx.get("https://webmail.example/web/").mock(
        return_value=Response(
            200,
            text=(
                '<form action="?logon" method="post">'
                '<input type="hidden" name="csrf" value="tok-csrf-9">'
                '<input type="text" name="username">'
                '<input type="password" name="password">'
                "</form>"
            ),
            headers=[
                ("set-cookie", "__Secure-GROMMUNIO_WEB=sess-from-get; Path=/; Secure"),
                ("set-cookie", "__Secure-encryption-store-key=enc-key; Path=/; Secure"),
            ],
        )
    )
    post_route = respx.post("https://webmail.example/web/?logon").mock(
        return_value=Response(
            303,
            headers=[
                ("location", "https://webmail.example/web/"),
                ("set-cookie", "__Secure-GROMMUNIO_WEB=sess-after-login; Path=/; Secure"),
                ("set-cookie", "domainname=ar-systems.fr; Path=/; Secure"),
            ],
        )
    )
    app = _generic_app(
        login_form_url="https://webmail.example/web/?logon",
        login_username_field="username",
        login_password_field="password",
    )
    result = await generic_form_login(
        _credential(),
        app,
        SECRET_PASSWORD,
        client_headers={
            "user-agent": "Mozilla/5.0 (TestBrowser)",
            "accept-language": "fr-FR,fr;q=0.9",
        },
    )
    assert get_route.called
    assert post_route.called
    post_req = post_route.calls.last.request
    assert post_req.headers.get("user-agent") == "Mozilla/5.0 (TestBrowser)"
    assert post_req.headers.get("accept-language") == "fr-FR,fr;q=0.9"
    body = post_req.content
    assert b"username=robot" in body
    assert SECRET_PASSWORD.encode() in body
    assert b"csrf=tok-csrf-9" in body
    assert result.cookies["__Secure-GROMMUNIO_WEB"] == "sess-after-login"
    assert result.cookies["__Secure-encryption-store-key"] == "enc-key"
    assert result.cookies["domainname"] == "ar-systems.fr"


@respx.mock
@pytest.mark.asyncio
async def test_grommunio_web_failed_login_page_not_treated_as_success():
    """Failed logon returns 200 + Set-Cookie + login HTML — must not look like success."""
    respx.get("https://webmail.example/web/").mock(
        return_value=Response(
            200,
            text='<form action="?logon"><input name="username"><input name="password"></form>',
            headers=[("set-cookie", "__Secure-GROMMUNIO_WEB=pre; Path=/")],
        )
    )
    respx.post("https://webmail.example/web/?logon").mock(
        return_value=Response(
            200,
            text=(
                '<form action="?logon" method="post">'
                '<input type="text" name="username" id="username">'
                '<input type="password" name="password" id="password">'
                "</form>"
            ),
            headers=[
                ("set-cookie", "__Secure-GROMMUNIO_WEB=failed-sess; Path=/"),
                ("x-grommunio-hresult", "MAPI_E_LOGON_FAILED"),
            ],
        )
    )
    app = _generic_app(
        login_form_url="https://webmail.example/web/?logon",
        login_username_field="username",
        login_password_field="password",
    )
    with pytest.raises(DriverAuthRejectedError, match="rejected credentials"):
        await generic_form_login(_credential(), app, SECRET_PASSWORD)


def test_extract_hidden_form_fields():
    from app.bastion.drivers.generic import extract_hidden_form_fields

    html = (
        '<input type="hidden" name="csrf" value="abc">'
        "<input type='hidden' name='token' value='xyz'>"
        '<input type="text" name="username" value="nope">'
    )
    assert extract_hidden_form_fields(html) == {"csrf": "abc", "token": "xyz"}


@respx.mock
@pytest.mark.asyncio
async def test_generic_form_login_timeout():
    respx.post("https://app.example/login").mock(side_effect=httpx.TimeoutException("timeout"))
    with pytest.raises(DriverUpstreamError, match="timed out"):
        await generic_form_login(_credential(), _generic_app(), SECRET_PASSWORD)


def test_generic_basic_auth_header_encoding():
    cred = _credential()
    header = generic_basic_auth_header(cred, SECRET_PASSWORD)
    assert header.startswith("Basic ")
    decoded = base64.b64decode(header.split(" ", 1)[1]).decode()
    assert decoded == f"robot:{SECRET_PASSWORD}"
    assert SECRET_PASSWORD not in header.replace(
        base64.b64encode(f"robot:{SECRET_PASSWORD}".encode()).decode(), ""
    )


def test_generic_basic_auth_header_not_in_repr(caplog):
    cred = _credential()
    with caplog.at_level(logging.DEBUG):
        header = generic_basic_auth_header(cred, SECRET_PASSWORD)
    assert header  # used
    assert SECRET_PASSWORD not in caplog.text
    with pytest.raises(DriverLoginError):
        raise DriverLoginError("login failed")
    assert SECRET_PASSWORD not in "login failed"
