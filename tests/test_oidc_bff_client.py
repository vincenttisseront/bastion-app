"""Unit tests for headless Keycloak OIDC BFF (PKCE + form POST)."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
import respx
from httpx import Response

from app.oidc_bff_client import (
    InvalidCredentialsError,
    OidcBffConfigError,
    UnsupportedAuthFlowError,
    perform_headless_login,
)
from app.sso_settings import Settings

KC = "http://keycloak.internal:8080"
REALM = "ar-systems"
AUTH = f"{KC}/realms/{REALM}/protocol/openid-connect/auth"
TOKEN = f"{KC}/realms/{REALM}/protocol/openid-connect/token"
LOGIN_ACTION = (
    f"{KC}/realms/{REALM}/login-actions/authenticate"
    "?session_code=abc&execution=exec1&client_id=bastion-bff&tab_id=tab1"
)
REDIRECT_URI = "https://portal.example/.bastion/oidc/callback"


def _settings() -> Settings:
    return Settings(
        environment="test",
        portal_domain="portal.example",
        oidc_session_jwt_secret="test-oidc-session-secret-not-shared",
        breakglass_jwt_secret="other-bg-secret",
        vault_portal_internal_token="other-vault-token",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
    )


def _bff_kwargs() -> dict:
    return {
        "keycloak_base_url": KC,
        "client_id": "bastion-bff",
        "client_secret": "bff-secret",
        "redirect_uri": REDIRECT_URI,
    }


def _login_html(*, error: bool = False) -> str:
    err = (
        '<span id="input-error" class="kc-feedback-text">'
        "Invalid username or password.</span>"
        if error
        else ""
    )
    return f"""
    <html><body>
      {err}
      <form id="kc-form-login" action="{LOGIN_ACTION}" method="post">
        <input type="hidden" name="credentialId" value="">
        <input type="text" name="username" value="">
        <input type="password" name="password" value="">
        <input type="submit" value="Sign In">
      </form>
    </body></html>
    """


def _otp_html() -> str:
    return f"""
    <html><body>
      <form id="kc-otp-login-form" action="{LOGIN_ACTION}&otp=1" method="post">
        <input type="text" name="otp" value="">
        <input type="submit" value="Submit">
      </form>
    </body></html>
    """


def _id_token(*, sub: str = "kc-sub-1", preferred: str = "alice") -> str:
    return jwt.encode(
        {"sub": sub, "preferred_username": preferred, "iss": f"{KC}/realms/{REALM}"},
        key="unit-test-hmac-key-32bytes-min!!",
        algorithm="HS256",
    )


@pytest.mark.asyncio
@respx.mock
async def test_headless_login_success():
    settings = _settings()
    auth_route = respx.get(AUTH).mock(
        return_value=Response(200, text=_login_html(), headers={"content-type": "text/html"})
    )
    login_route = respx.post(url__startswith=f"{KC}/realms/{REALM}/login-actions/authenticate").mock(
        return_value=Response(
            302,
            headers={
                "Location": f"{REDIRECT_URI}?code=auth-code-1&state=will-be-checked",
            },
        )
    )
    token_route = respx.post(TOKEN).mock(
        return_value=Response(
            200,
            json={
                "access_token": "access-xyz",
                "refresh_token": "refresh-xyz",
                "id_token": _id_token(),
                "expires_in": 300,
                "token_type": "Bearer",
            },
        )
    )

    def _login_with_state(request):
        assert auth_route.called
        auth_req = auth_route.calls.last.request
        state = parse_qs(urlparse(str(auth_req.url)).query)["state"][0]
        return Response(
            302,
            headers={"Location": f"{REDIRECT_URI}?code=auth-code-1&state={state}"},
        )

    login_route.side_effect = _login_with_state

    result = await perform_headless_login(
        REALM, "alice", "s3cret", settings=settings, **_bff_kwargs()
    )

    assert result.access_token == "access-xyz"
    assert result.refresh_token == "refresh-xyz"
    assert result.sub == "kc-sub-1"
    assert result.preferred_username == "alice"
    assert result.expires_in == 300
    assert auth_route.called and login_route.called and token_route.called

    auth_q = parse_qs(urlparse(str(auth_route.calls.last.request.url)).query)
    assert auth_q["client_id"] == ["bastion-bff"]
    assert auth_q["code_challenge_method"] == ["S256"]
    assert auth_q["response_type"] == ["code"]
    challenge = auth_q["code_challenge"][0]
    assert len(challenge) >= 40

    body = dict(parse_qs(token_route.calls.last.request.content.decode()))
    verifier = body["code_verifier"][0]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    assert expected == challenge
    assert body["code"] == ["auth-code-1"]
    assert body["client_secret"] == ["bff-secret"]
    assert "password" not in body
    assert "s3cret" not in token_route.calls.last.request.content.decode()


@pytest.mark.asyncio
async def test_headless_login_missing_config_raises():
    with pytest.raises(OidcBffConfigError, match="non configuré"):
        await perform_headless_login(
            REALM, "alice", "s3cret", settings=_settings(), db=None
        )


@pytest.mark.asyncio
@respx.mock
async def test_headless_login_invalid_password():
    settings = _settings()
    respx.get(AUTH).mock(
        return_value=Response(200, text=_login_html(), headers={"content-type": "text/html"})
    )
    respx.post(url__startswith=f"{KC}/realms/{REALM}/login-actions/authenticate").mock(
        return_value=Response(
            200,
            text=_login_html(error=True),
            headers={"content-type": "text/html"},
        )
    )

    with pytest.raises(InvalidCredentialsError):
        await perform_headless_login(
            REALM, "alice", "wrong", settings=settings, **_bff_kwargs()
        )


@pytest.mark.asyncio
@respx.mock
async def test_headless_login_mfa_required():
    settings = _settings()
    respx.get(AUTH).mock(
        return_value=Response(200, text=_login_html(), headers={"content-type": "text/html"})
    )
    respx.post(url__startswith=f"{KC}/realms/{REALM}/login-actions/authenticate").mock(
        return_value=Response(
            200,
            text=_otp_html(),
            headers={"content-type": "text/html"},
        )
    )

    with pytest.raises(UnsupportedAuthFlowError, match="kc-otp-login-form"):
        await perform_headless_login(
            REALM, "alice", "s3cret", settings=settings, **_bff_kwargs()
        )


@pytest.mark.asyncio
@respx.mock
async def test_headless_login_mfa_via_redirect_location():
    settings = _settings()
    respx.get(AUTH).mock(
        return_value=Response(200, text=_login_html(), headers={"content-type": "text/html"})
    )
    respx.post(url__startswith=f"{KC}/realms/{REALM}/login-actions/authenticate").mock(
        return_value=Response(
            302,
            headers={
                "Location": (
                    f"{KC}/realms/{REALM}/login-actions/authenticate"
                    "?execution=otp&client_id=bastion-bff"
                )
            },
        )
    )

    with pytest.raises(UnsupportedAuthFlowError, match="étape interactive"):
        await perform_headless_login(
            REALM, "alice", "s3cret", settings=settings, **_bff_kwargs()
        )
