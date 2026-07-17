"""CrushFTP driver unit tests with respx-mocked httpx."""

from __future__ import annotations

import httpx
import pytest
import respx
from httpx import Response

from app.bastion.drivers.base import RoboticLoginError
from app.bastion.drivers.crushftp import CrushFTPDriver

BASE = "https://crush.example"
LOGIN_URL = f"{BASE}/WebInterface/function/"
LOGIN_HTML = f"{BASE}/WebInterface/login.html"


@respx.mock
@pytest.mark.asyncio
async def test_login_ok_extracts_cookies():
    route = respx.post(LOGIN_URL).mock(
        return_value=Response(
            200,
            text="<commandResult><response>success</response></commandResult>",
            headers=[
                ("set-cookie", "CrushAuth=ABCDEFGH1234; Path=/"),
                ("set-cookie", "currentAuth=1234; Path=/"),
            ],
        )
    )
    driver = CrushFTPDriver()
    session = await driver.login(BASE, "robot", "secret")
    assert route.called
    assert session.cookies["CrushAuth"] == "ABCDEFGH1234"
    assert session.cookies["currentAuth"] == "1234"
    # Password must not appear in the recorded request body in assertions we care about —
    # we only check the driver returned structured cookies.
    body = route.calls.last.request.content.decode()
    assert "command=login" in body
    assert "username=robot" in body


@respx.mock
@pytest.mark.asyncio
async def test_login_rejected():
    respx.post(LOGIN_URL).mock(
        return_value=Response(200, text="<response>failure</response>")
    )
    driver = CrushFTPDriver()
    with pytest.raises(RoboticLoginError, match="rejected"):
        await driver.login(BASE, "robot", "wrong")


@respx.mock
@pytest.mark.asyncio
async def test_login_timeout():
    respx.post(LOGIN_URL).mock(side_effect=httpx.TimeoutException("timeout"))
    driver = CrushFTPDriver()
    with pytest.raises(RoboticLoginError, match="timed out"):
        await driver.login(BASE, "robot", "secret")


@respx.mock
@pytest.mark.asyncio
async def test_get_username_ok():
    respx.post(LOGIN_URL).mock(
        side_effect=[
            Response(
                200,
                text="<response>success</response>",
                headers=[("set-cookie", "CrushAuth=TOKENTOKEN1234; Path=/")],
            ),
            Response(200, text="<response>robot</response>"),
        ]
    )
    driver = CrushFTPDriver()
    session = await driver.login(BASE, "robot", "secret")
    assert await driver.get_username(session) == "robot"


@respx.mock
@pytest.mark.asyncio
async def test_fingerprint_detects_crushftp():
    respx.get(LOGIN_HTML).mock(
        return_value=Response(200, text="<html>CrushFTP WebInterface</html>")
    )
    driver = CrushFTPDriver()
    assert await driver.fingerprint(BASE) is True
