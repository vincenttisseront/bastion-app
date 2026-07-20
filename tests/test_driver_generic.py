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
async def test_generic_form_login_no_cookies_raises():
    respx.post("https://app.example/login").mock(return_value=Response(200))
    with pytest.raises(DriverLoginError, match="no session cookies"):
        await generic_form_login(_credential(), _generic_app(), SECRET_PASSWORD)


@respx.mock
@pytest.mark.asyncio
async def test_generic_form_login_401_raises():
    respx.post("https://app.example/login").mock(return_value=Response(401))
    with pytest.raises(DriverLoginError, match="no session cookies"):
        await generic_form_login(_credential(), _generic_app(), SECRET_PASSWORD)


@respx.mock
@pytest.mark.asyncio
async def test_generic_form_login_timeout():
    respx.post("https://app.example/login").mock(side_effect=httpx.TimeoutException("timeout"))
    with pytest.raises(DriverLoginError, match="timed out"):
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
