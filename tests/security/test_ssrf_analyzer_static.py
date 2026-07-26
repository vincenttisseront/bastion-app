"""Guards for login-form analyzer (timeout/size/scheme — not private-IP SSRF)."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from app.bastion import login_form_analyzer as mod
from app.bastion.login_form_analyzer import AnalyzeLoginFormError, validate_analyze_url


def test_analyzer_has_timeout_and_redirect_limits():
    assert mod.TIMEOUT_SECONDS <= 10.0
    assert mod.MAX_REDIRECTS <= 5
    assert mod.MAX_BODY_BYTES <= 2 * 1024 * 1024


def test_validate_analyze_url_rejects_non_http():
    with pytest.raises(AnalyzeLoginFormError) as exc:
        validate_analyze_url("ftp://127.0.0.1/")
    assert exc.value.error == "invalid_url"


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000/health",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "https://dolibarr.ar-systems.fr/login",
        "http://[::1]/",
    ],
)
def test_validate_analyze_url_allows_private_and_internal(url: str):
    """Private/LAN hosts are in-scope: bastion apps live on internal networks."""
    assert validate_analyze_url(url) == url


@pytest.mark.asyncio
@respx.mock
async def test_fetch_allows_redirect_to_private_ip():
    public = "https://public.example/login"
    internal = "http://10.0.0.5/internal"
    html = """
    <form method="post" action="/do">
      <input type="text" name="user">
      <input type="password" name="password">
    </form>
    """
    respx.get(public).mock(
        return_value=Response(302, headers={"Location": internal})
    )
    respx.get(internal).mock(return_value=Response(200, text=html))
    final, body = await mod.fetch_login_page(public)
    assert final == internal
    assert "password" in body


@pytest.mark.asyncio
@respx.mock
async def test_fetch_rejects_redirect_to_non_http_scheme():
    public = "https://public.example/login"
    respx.get(public).mock(
        return_value=Response(302, headers={"Location": "file:///etc/passwd"})
    )
    with pytest.raises(AnalyzeLoginFormError) as exc:
        await mod.fetch_login_page(public)
    assert exc.value.error == "invalid_url"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_rfc1918_literal_url_works():
    url = "http://10.5.0.20/login"
    html = """
    <form method="post">
      <input type="text" name="username">
      <input type="password" name="password">
    </form>
    """
    respx.get(url).mock(return_value=Response(200, text=html))
    final, body = await mod.fetch_login_page(url)
    assert final == url
    assert "password" in body
