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
    with pytest.raises(RoboticLoginError, match="login rejected"):
        await driver.login(BASE, "robot", "wrong")


@respx.mock
@pytest.mark.asyncio
async def test_login_ip_banned_hint_and_warning(caplog):
    """CrushFTP anti-hammering ban (DENIAL in CrushFTP.log) must surface both in
    the raised error and as a bastion-side WARNING with the body excerpt."""
    import logging

    ban_text = (
        "---Your IP is banned, no further requests will be processed "
        "from this IP---"
    )
    respx.post(LOGIN_URL).mock(return_value=Response(200, text=ban_text))
    driver = CrushFTPDriver()
    with caplog.at_level(logging.WARNING, logger="app.bastion.drivers.crushftp"):
        with pytest.raises(RoboticLoginError, match="bannie par CrushFTP"):
            await driver.login(BASE, "robot", "secret")

    warnings = [r for r in caplog.records if "CrushFTP login rejected" in r.message]
    assert len(warnings) == 1
    msg = warnings[0].getMessage()
    assert "anti-hammering" in msg
    assert "Your IP is banned" in msg  # body excerpt mirrored in bastion logs
    assert "secret" not in msg  # never the password


@respx.mock
@pytest.mark.asyncio
async def test_login_session_limit_hint():
    respx.post(LOGIN_URL).mock(
        return_value=Response(
            200, text="421 Max simultaneous user limit reached."
        )
    )
    driver = CrushFTPDriver()
    with pytest.raises(RoboticLoginError, match="sessions simultanées"):
        await driver.login(BASE, "robot", "secret")


@respx.mock
@pytest.mark.asyncio
async def test_login_sso_redirect_message():
    respx.post(LOGIN_URL).mock(
        return_value=Response(
            302, headers={"location": "https://sso.example/auth"}, text=""
        )
    )
    driver = CrushFTPDriver()
    with pytest.raises(RoboticLoginError, match="redirected|SSO"):
        await driver.login(BASE, "robot", "secret")


@respx.mock
@pytest.mark.asyncio
async def test_login_html_response_message():
    respx.post(LOGIN_URL).mock(
        return_value=Response(200, text="<!DOCTYPE html><html><body>login</body></html>")
    )
    driver = CrushFTPDriver()
    with pytest.raises(RoboticLoginError, match="HTML|SSO"):
        await driver.login(BASE, "robot", "secret")


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
            Response(
                200,
                text=(
                    "<loginResult><response>success</response>"
                    "<username>robot</username></loginResult>"
                ),
            ),
        ]
    )
    driver = CrushFTPDriver()
    session = await driver.login(BASE, "robot", "secret")
    assert await driver.get_username(session) == "robot"


@respx.mock
@pytest.mark.asyncio
async def test_get_username_extracts_from_username_tag_not_response():
    """CrushFTP puts success/failure in <response> and the real login in <username>."""
    respx.post(LOGIN_URL).mock(
        side_effect=[
            Response(
                200,
                text="<response>success</response>",
                headers=[("set-cookie", "CrushAuth=TOKENTOKEN1234; Path=/")],
            ),
            Response(
                200,
                text=(
                    "<loginResult><response>success</response>"
                    "<username>vincent</username></loginResult>"
                ),
            ),
        ]
    )
    driver = CrushFTPDriver()
    session = await driver.login(BASE, "robot", "secret")
    identity = await driver.get_username(session)
    assert identity == "vincent"
    assert identity != "success"


@respx.mock
@pytest.mark.asyncio
async def test_get_username_missing_username_tag_despite_success():
    respx.post(LOGIN_URL).mock(
        side_effect=[
            Response(
                200,
                text="<response>success</response>",
                headers=[("set-cookie", "CrushAuth=TOKENTOKEN1234; Path=/")],
            ),
            Response(200, text="<loginResult><response>success</response></loginResult>"),
        ]
    )
    driver = CrushFTPDriver()
    session = await driver.login(BASE, "robot", "secret")
    with pytest.raises(RoboticLoginError, match="missing username"):
        await driver.get_username(session)


@respx.mock
@pytest.mark.asyncio
async def test_fingerprint_detects_crushftp():
    respx.get(LOGIN_HTML).mock(
        return_value=Response(200, text="<html>CrushFTP WebInterface</html>")
    )
    driver = CrushFTPDriver()
    assert await driver.fingerprint(BASE) is True


@respx.mock
@pytest.mark.asyncio
async def test_logout_posts_command_best_effort():
    route = respx.post(LOGIN_URL).mock(return_value=Response(200, text="<response>success</response>"))
    driver = CrushFTPDriver()
    from app.bastion.drivers.crushftp import CrushFTPSession

    session = CrushFTPSession(
        cookies={"CrushAuth": "ABCDEFGH1234", "currentAuth": "1234"},
        base_url=BASE + "/",
    )
    await driver.logout(session)
    assert route.called
    body = route.calls.last.request.content.decode()
    assert "command=logout" in body
    assert "c2f=1234" in body


@respx.mock
@pytest.mark.asyncio
async def test_logout_swallows_network_errors():
    respx.post(LOGIN_URL).mock(side_effect=httpx.ConnectError("down"))
    driver = CrushFTPDriver()
    from app.bastion.drivers.crushftp import CrushFTPSession

    session = CrushFTPSession(
        cookies={"CrushAuth": "ABCDEFGH1234", "currentAuth": "1234"},
        base_url=BASE + "/",
    )
    await driver.logout(session)  # must not raise
