"""Tests for login form HTML analyzer (vault generic_form pre-fill)."""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest
import respx
from httpx import Response

from app.bastion.login_form_analyzer import (
    AnalyzeLoginFormError,
    analyze_html,
    analyze_login_form_url,
    is_likely_dynamic,
)


ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

USER_HEADERS = {
    "X-Email": "alice@example.com",
    "X-Preferred-Username": "alice",
    "X-Groups": "team-ops",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

PAGE_URL = "https://app.example/login"

_PUBLIC_IP = ["8.8.8.8"]


@pytest.fixture(autouse=True)
def _allow_example_hosts_dns():
    """Analyzer resolves hosts before fetch — keep example.test hosts on a public IP."""
    with patch(
        "app.bastion.login_form_analyzer.resolve_hostname_ips",
        return_value=_PUBLIC_IP,
    ):
        yield


def test_analyze_login_form_single():
    html = """
    <html><body>
      <form action="/do-login" method="post">
        <input type="hidden" name="remember" value="1">
        <input type="text" name="username" id="user">
        <input type="password" name="password">
        <button type="submit">Go</button>
      </form>
    </body></html>
    """
    forms = analyze_html(html, PAGE_URL)
    assert len(forms) == 1
    form = forms[0]
    assert form["action"] == "https://app.example/do-login"
    assert form["method"] == "POST"
    assert form["method_explicit"] is True
    assert form["username_field"] == {"name": "username", "confidence": "high"}
    assert form["password_field"] == {"name": "password", "confidence": "high"}
    assert form["hidden_fields"] == [
        {"name": "remember", "value": "1", "likely_dynamic": False}
    ]


def test_analyze_login_form_multiple():
    html = """
    <html><body>
      <form action="/search" method="get">
        <input type="text" name="q">
      </form>
      <form action="/login-a" method="post">
        <input type="text" name="user">
        <input type="password" name="pass">
      </form>
      <form action="/login-b" method="post">
        <input type="email" name="email">
        <input type="password" name="pwd">
        <input type="hidden" name="x" value="1">
      </form>
    </body></html>
    """
    forms = analyze_html(html, PAGE_URL)
    assert len(forms) == 2
    assert forms[0]["action"] == "https://app.example/login-a"
    assert forms[0]["password_field"]["name"] == "pass"
    assert forms[1]["action"] == "https://app.example/login-b"
    assert forms[1]["username_field"]["name"] == "email"
    assert forms[1]["password_field"]["name"] == "pwd"


def test_analyze_login_form_no_password():
    html = """
    <html><body>
      <form action="/search"><input type="text" name="q"></form>
      <div>No password here</div>
    </body></html>
    """
    forms = analyze_html(html, PAGE_URL)
    assert forms == []


def test_analyze_login_form_hidden_dynamic():
    assert is_likely_dynamic("1") is False
    assert is_likely_dynamic("true") is False
    assert is_likely_dynamic("remember") is False
    token = "a91fB3cDeF0123456789AbCdEf"
    assert len(token) > 20
    assert is_likely_dynamic(token) is True

    html = f"""
    <form method="post" action="/login">
      <input type="hidden" name="remember" value="1">
      <input type="hidden" name="token" value="{token}">
      <input type="text" name="login">
      <input type="password" name="password">
    </form>
    """
    form = analyze_html(html, PAGE_URL)[0]
    by_name = {h["name"]: h for h in form["hidden_fields"]}
    assert by_name["remember"]["likely_dynamic"] is False
    assert by_name["token"]["likely_dynamic"] is True


def test_analyze_login_form_action_relative():
    html = """
    <form action="auth/submit.php" method="POST">
      <input type="text" name="user">
      <input type="password" name="password">
    </form>
    """
    form = analyze_html(html, "https://dolibarr.example/index.php")[0]
    assert form["action"] == "https://dolibarr.example/auth/submit.php"


def test_analyze_login_form_method_not_explicit():
    html = """
    <form action="/login">
      <input type="text" name="username">
      <input type="password" name="password">
    </form>
    """
    form = analyze_html(html, PAGE_URL)[0]
    assert form["method_explicit"] is False
    assert form["method"] == "POST"


def test_analyze_login_form_missing_action_uses_page_url():
    html = """
    <form method="post">
      <input type="email" name="mail">
      <input type="password" name="password">
    </form>
    """
    form = analyze_html(html, PAGE_URL)[0]
    assert form["action"] == PAGE_URL
    assert form["username_field"]["name"] == "mail"


@pytest.mark.asyncio
@respx.mock
async def test_analyze_login_form_fetch_timeout():
    respx.get(PAGE_URL).mock(side_effect=httpx.TimeoutException("timed out"))
    with pytest.raises(AnalyzeLoginFormError) as exc_info:
        await analyze_login_form_url(PAGE_URL)
    assert exc_info.value.error == "timeout"
    assert exc_info.value.status_code == 504


@pytest.mark.asyncio
@respx.mock
async def test_analyze_login_form_fetch_http_error():
    respx.get(PAGE_URL).mock(return_value=Response(503, text="unavailable"))
    with pytest.raises(AnalyzeLoginFormError) as exc_info:
        await analyze_login_form_url(PAGE_URL)
    assert exc_info.value.error == "fetch_failed"
    assert "503" in exc_info.value.message


@pytest.mark.asyncio
@respx.mock
async def test_analyze_login_form_endpoint_ok(client):
    html = """
    <form action="/index.php?dol_login" method="post">
      <input type="hidden" name="remember" value="1">
      <input type="text" name="username">
      <input type="password" name="password">
    </form>
    """
    respx.get("https://dolibarr.example/").mock(return_value=Response(200, text=html))
    resp = client.post(
        "/admin/apps/analyze-login-form",
        headers=ADMIN_HEADERS,
        json={"url": "https://dolibarr.example/"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["forms_found"] == 1
    assert data["forms"][0]["username_field"]["name"] == "username"
    assert data["forms"][0]["password_field"]["name"] == "password"
    assert data["forms"][0]["method"] == "POST"


@pytest.mark.asyncio
@respx.mock
async def test_analyze_login_form_endpoint_no_form(client):
    respx.get(PAGE_URL).mock(return_value=Response(200, text="<html><body>hi</body></html>"))
    resp = client.post(
        "/admin/apps/analyze-login-form",
        headers=ADMIN_HEADERS,
        json={"url": PAGE_URL},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "no_form_found"
    assert "mot de passe" in body["message"].lower()


@pytest.mark.asyncio
@respx.mock
async def test_analyze_login_form_endpoint_timeout(client):
    respx.get(PAGE_URL).mock(side_effect=httpx.TimeoutException("timed out"))
    resp = client.post(
        "/admin/apps/analyze-login-form",
        headers=ADMIN_HEADERS,
        json={"url": PAGE_URL},
    )
    assert resp.status_code == 504
    assert resp.json()["error"] == "timeout"


def test_analyze_login_form_endpoint_forbidden(client):
    resp = client.post(
        "/admin/apps/analyze-login-form",
        headers=USER_HEADERS,
        json={"url": PAGE_URL},
    )
    assert resp.status_code == 403


def test_analyze_login_form_endpoint_invalid_url(client):
    resp = client.post(
        "/admin/apps/analyze-login-form",
        headers=ADMIN_HEADERS,
        json={"url": "ftp://evil.example/"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_url"
