"""Unit tests for headless Keycloak OIDC BFF (PKCE + form POST)."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import Response
from jwt.algorithms import RSAAlgorithm

from app.oidc_bff_client import (
    InvalidCredentialsError,
    OidcBffConfigError,
    UnsupportedAuthFlowError,
    _absolute_action_url,
    extract_groups_from_oidc_claims,
    perform_headless_login,
)
from app.sso_settings import Settings

KC = "http://keycloak.internal:8080"
REALM = "ar-systems"
AUTH = f"{KC}/realms/{REALM}/protocol/openid-connect/auth"
TOKEN = f"{KC}/realms/{REALM}/protocol/openid-connect/token"
DISCOVERY = f"{KC}/realms/{REALM}/.well-known/openid-configuration"
CERTS = f"{KC}/realms/{REALM}/protocol/openid-connect/certs"
LOGIN_ACTION = (
    f"{KC}/realms/{REALM}/login-actions/authenticate"
    "?session_code=abc&execution=exec1&client_id=bastion-bff&tab_id=tab1"
)
REDIRECT_URI = "https://portal.example/.bastion/oidc/callback"
CLIENT_ID = "bastion-bff"

_RSA_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_RSA_PUBLIC = _RSA_PRIVATE.public_key()
_JWK = json.loads(RSAAlgorithm.to_jwk(_RSA_PUBLIC))
_JWK.update({"kid": "test-key", "alg": "RS256", "use": "sig"})


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
        "client_id": CLIENT_ID,
        "client_secret": "bff-secret",
        "redirect_uri": REDIRECT_URI,
    }


def _mock_oidc_discovery() -> None:
    respx.get(DISCOVERY).mock(
        return_value=Response(
            200,
            json={
                "issuer": f"{KC}/realms/{REALM}",
                "jwks_uri": CERTS,
            },
        )
    )
    respx.get(CERTS).mock(return_value=Response(200, json={"keys": [_JWK]}))


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


def _id_token(*, sub: str = "kc-sub-1", preferred: str = "alice", groups=None) -> str:
    now = int(time.time())
    payload = {
        "sub": sub,
        "preferred_username": preferred,
        "iss": f"{KC}/realms/{REALM}",
        "aud": CLIENT_ID,
        "exp": now + 300,
        "iat": now,
    }
    if groups is not None:
        payload["groups"] = groups
    return jwt.encode(
        payload,
        key=_RSA_PRIVATE,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )


@pytest.mark.asyncio
@respx.mock
async def test_headless_login_success():
    settings = _settings()
    _mock_oidc_discovery()
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
    assert result.groups == ()
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
    with pytest.raises(OidcBffConfigError, match="db session required|non configuré"):
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
    otp_url = (
        f"{KC}/realms/{REALM}/login-actions/authenticate"
        "?execution=otp&client_id=bastion-bff"
    )
    respx.post(url__startswith=f"{KC}/realms/{REALM}/login-actions/authenticate").mock(
        return_value=Response(302, headers={"Location": otp_url})
    )
    respx.get(otp_url).mock(
        return_value=Response(200, text=_otp_html(), headers={"content-type": "text/html"})
    )

    with pytest.raises(UnsupportedAuthFlowError, match="kc-otp-login-form"):
        await perform_headless_login(
            REALM, "alice", "s3cret", settings=settings, **_bff_kwargs()
        )


def test_extract_groups_from_oidc_claims_paths_and_csv():
    from app.oidc_bff_client import extract_groups_from_oidc_claims

    assert extract_groups_from_oidc_claims(
        {"groups": ["/ARSYSTEMS-Users", "/portal-admins"]}
    ) == ("ARSYSTEMS-Users", "portal-admins")
    assert extract_groups_from_oidc_claims(
        {"groups": "ARSYSTEMS-Users,portal-admins"}
    ) == ("ARSYSTEMS-Users", "portal-admins")
    assert extract_groups_from_oidc_claims(
        {"groups": ["/dup"]},
        {"groups": ["dup", "/other"]},
    ) == ("dup", "other")
    assert extract_groups_from_oidc_claims(None, {}) == ()


@pytest.mark.asyncio
@respx.mock
async def test_headless_login_extracts_groups_from_id_token():
    settings = _settings()
    _mock_oidc_discovery()
    respx.get(AUTH).mock(
        return_value=Response(200, text=_login_html(), headers={"content-type": "text/html"})
    )

    def _login_with_state(request):
        auth_req = respx.calls[0].request
        state = parse_qs(urlparse(str(auth_req.url)).query)["state"][0]
        return Response(
            302,
            headers={"Location": f"{REDIRECT_URI}?code=auth-code-1&state={state}"},
        )

    respx.post(url__startswith=f"{KC}/realms/{REALM}/login-actions/authenticate").mock(
        side_effect=_login_with_state
    )
    respx.post(TOKEN).mock(
        return_value=Response(
            200,
            json={
                "access_token": "access-xyz",
                "id_token": _id_token(groups=["/ARSYSTEMS-Users"]),
                "expires_in": 300,
                "token_type": "Bearer",
            },
        )
    )

    result = await perform_headless_login(
        REALM, "alice", "s3cret", settings=settings, **_bff_kwargs()
    )
    assert result.groups == ("ARSYSTEMS-Users",)


def test_absolute_action_url_rewrites_public_frontend_to_internal_base():
    public = (
        "https://sso.example/realms/clients/login-actions/authenticate"
        "?session_code=abc&execution=e1&client_id=bff&tab_id=t1"
    )
    rewritten = _absolute_action_url(public, KC)
    assert rewritten.startswith(f"{KC}/realms/clients/login-actions/authenticate")
    assert "session_code=abc" in rewritten
    assert "sso.example" not in rewritten


@pytest.mark.asyncio
@respx.mock
async def test_headless_login_posts_to_internal_when_form_action_is_public():
    """Keycloak embeds frontend URL in form action — BFF must POST to internal base."""
    settings = _settings()
    _mock_oidc_discovery()
    public_action = (
        "https://sso.public.example/realms/ar-systems/login-actions/authenticate"
        "?session_code=abc&execution=exec1&client_id=bastion-bff&tab_id=tab1"
    )
    html = f"""
    <html><body>
      <form id="kc-form-login" action="{public_action}" method="post">
        <input type="text" name="username" value="">
        <input type="password" name="password" value="">
      </form>
    </body></html>
    """
    respx.get(AUTH).mock(
        return_value=Response(200, text=html, headers={"content-type": "text/html"})
    )
    public_post = respx.post(url__startswith="https://sso.public.example/").mock(
        return_value=Response(400, text="Cookie not found")
    )

    def _login_with_state(request):
        assert str(request.url).startswith(KC)
        auth_req = respx.calls[0].request
        state = parse_qs(urlparse(str(auth_req.url)).query)["state"][0]
        return Response(
            302,
            headers={"Location": f"{REDIRECT_URI}?code=auth-code-1&state={state}"},
        )

    internal_post = respx.post(
        url__startswith=f"{KC}/realms/{REALM}/login-actions/authenticate"
    ).mock(side_effect=_login_with_state)
    respx.post(TOKEN).mock(
        return_value=Response(
            200,
            json={
                "access_token": "access-xyz",
                "id_token": _id_token(),
                "expires_in": 300,
                "token_type": "Bearer",
            },
        )
    )

    result = await perform_headless_login(
        REALM, "alice", "s3cret", settings=settings, **_bff_kwargs()
    )
    assert result.sub == "kc-sub-1"
    assert internal_post.called
    assert not public_post.called


@pytest.mark.asyncio
@respx.mock
async def test_headless_login_follows_frontend_redirect_host():
    """Auth 302 to public frontend: keep cookies on that host (do not pin internal)."""
    settings = _settings()
    _mock_oidc_discovery()
    public_origin = "https://sso.public.example"
    public_login = (
        f"{public_origin}/realms/{REALM}/login-actions/authenticate"
        "?session_code=abc&execution=exec1&client_id=bastion-bff&tab_id=tab1"
    )
    html = f"""
    <html><body>
      <form id="kc-form-login" action="{public_login}" method="post">
        <input type="text" name="username" value="">
        <input type="password" name="password" value="">
      </form>
    </body></html>
    """
    respx.get(AUTH).mock(
        return_value=Response(302, headers={"Location": public_login})
    )
    public_get = respx.get(url__startswith=f"{public_origin}/realms/").mock(
        return_value=Response(200, text=html, headers={"content-type": "text/html"})
    )
    # Must NOT re-hit internal login-actions for the HTML (would drop public cookies).
    internal_login_get = respx.get(
        url__startswith=f"{KC}/realms/{REALM}/login-actions/authenticate"
    ).mock(return_value=Response(400, text="should not get HTML here"))

    def _login_with_state(request):
        assert str(request.url).startswith(public_origin)
        auth_calls = [
            c for c in respx.calls if str(c.request.url).startswith(AUTH)
        ]
        state = parse_qs(urlparse(str(auth_calls[0].request.url)).query)["state"][0]
        return Response(
            302,
            headers={"Location": f"{REDIRECT_URI}?code=auth-code-1&state={state}"},
        )

    public_post = respx.post(
        url__startswith=f"{public_origin}/realms/{REALM}/login-actions/authenticate"
    ).mock(side_effect=_login_with_state)
    respx.post(TOKEN).mock(
        return_value=Response(
            200,
            json={
                "access_token": "access-xyz",
                "id_token": _id_token(),
                "expires_in": 300,
                "token_type": "Bearer",
            },
        )
    )

    result = await perform_headless_login(
        REALM, "alice", "s3cret", settings=settings, **_bff_kwargs()
    )
    assert result.sub == "kc-sub-1"
    assert public_get.called
    assert public_post.called
    assert not internal_login_get.called
