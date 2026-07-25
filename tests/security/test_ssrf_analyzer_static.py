"""Static proofs for login-form analyzer SSRF controls (no network to staging)."""

from __future__ import annotations

import ipaddress
from unittest.mock import patch

import httpx
import pytest
import respx
from httpx import Response

from app.bastion import login_form_analyzer as mod
from app.bastion.login_form_analyzer import (
    AnalyzeLoginFormError,
    assert_url_host_allowed,
    is_blocked_ip,
    validate_analyze_url,
)


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
        "http://localhost/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://[::1]/",
    ],
)
def test_validate_analyze_url_blocks_sensitive_targets(url: str):
    with pytest.raises(AnalyzeLoginFormError) as exc:
        validate_analyze_url(url)
    assert exc.value.error in ("url_blocked", "dns_failed", "invalid_url")
    assert exc.value.status_code == 400


def test_is_blocked_ip_covers_metadata_and_private():
    assert is_blocked_ip(ipaddress.ip_address("169.254.169.254"))
    assert is_blocked_ip(ipaddress.ip_address("10.1.2.3"))
    assert is_blocked_ip(ipaddress.ip_address("127.0.0.1"))
    assert not is_blocked_ip(ipaddress.ip_address("8.8.8.8"))


def test_assert_url_host_allowed_rejects_after_dns_to_private():
    with patch(
        "app.bastion.login_form_analyzer.resolve_hostname_ips",
        return_value=["10.0.0.9"],
    ):
        with pytest.raises(AnalyzeLoginFormError) as exc:
            assert_url_host_allowed("https://evil.example/")
        assert exc.value.error == "url_blocked"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_rejects_redirect_to_private_ip():
    """First hop public; Location points at RFC1918 — must not follow."""
    public = "https://public.example/login"
    with patch(
        "app.bastion.login_form_analyzer.resolve_hostname_ips",
        side_effect=lambda host: (
            ["8.8.8.8"] if host == "public.example" else ["10.0.0.5"]
        ),
    ):
        respx.get(public).mock(
            return_value=Response(
                302,
                headers={"Location": "http://10.0.0.5/internal"},
            )
        )
        with pytest.raises(AnalyzeLoginFormError) as exc:
            await mod.fetch_login_page(public)
        assert exc.value.error == "url_blocked"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_public_url_still_works():
    public = "https://app.example/login"
    html = """
    <form method="post" action="/do">
      <input type="text" name="user">
      <input type="password" name="password">
    </form>
    """
    with patch(
        "app.bastion.login_form_analyzer.resolve_hostname_ips",
        return_value=["8.8.8.8"],
    ):
        respx.get(public).mock(return_value=Response(200, text=html))
        final, body = await mod.fetch_login_page(public)
        assert final == public
        assert "password" in body
