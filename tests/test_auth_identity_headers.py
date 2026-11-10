"""Identity headers emitted by the auth_request handlers, and the internal token.

Starlette encodes response headers as latin-1: an unencodable claim used to
fail the whole auth_request with a 500 (user locked out of every vhost).
"""

from __future__ import annotations

import httpx
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request
from starlette.responses import Response

from app.auth.auth_request import (
    _forward_auth_request_headers,
    email_from_username_enabled,
    safe_groups_header,
    safe_header_value,
)
from app.security import require_nginx_internal_token
from app.sso_settings import Settings


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("  alice@example.com  ", "alice@example.com"),
        ("Équipe-Réseau", "Équipe-Réseau"),
        ("Zespół", ""),
        ("管理者", ""),
        ("alice\r\nX-Auth-Request-Groups: portal-admins", ""),
        ("alice\x00", ""),
        ("", ""),
        (None, ""),
    ],
)
def test_safe_header_value(raw, expected):
    value = safe_header_value(raw)
    assert value == expected
    Response(status_code=200, headers={"X-Test": value})  # must not raise


def test_safe_groups_header_drops_unsafe_names_only():
    groups = ["ops", "Zespół", "x,portal-admins", " ", "Équipe"]
    assert safe_groups_header(groups) == "ops,Équipe"
    assert safe_groups_header([]) == ""


def test_forward_auth_request_headers_survives_utf8_from_oauth2_proxy():
    upstream = httpx.Headers(
        [
            (b"X-Auth-Request-User", b"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            (b"X-Auth-Request-Email", b"alice@example.com"),
            (b"X-Auth-Request-Preferred-Username", "Łukasz".encode()),
            (b"X-Auth-Request-Groups", "ops,Zespół,admins".encode()),
            (b"Set-Cookie", b"_oauth2_proxy=secret"),
        ]
    )
    forwarded = _forward_auth_request_headers(upstream)
    assert forwarded == {
        "X-Auth-Request-User": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "X-Auth-Request-Email": "alice@example.com",
        "X-Auth-Request-Groups": "ops,admins",
    }
    Response(status_code=202, headers=forwarded)  # must not raise


def test_email_from_username_is_opt_in():
    base = {
        "vault_portal_internal_token": "test-secret",
        "portal_secret_encryption_key": "test-encryption-key-for-pytest-only",
        "database_url": "sqlite://",
    }
    assert email_from_username_enabled(Settings(**base)) is False
    assert (
        email_from_username_enabled(Settings(**base, trusted_email_from_username=True))
        is True
    )
    # A partial / mocked settings object must never enable the fallback.
    assert email_from_username_enabled(object()) is False  # type: ignore[arg-type]


def _request(headers: dict[str, bytes]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(k.lower().encode(), v) for k, v in headers.items()],
        }
    )


def _token_settings(token: str = "internal-token-value") -> Settings:
    return Settings(
        vault_portal_internal_token=token,
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )


def test_require_nginx_internal_token_accepts_header_and_bearer():
    settings = _token_settings()
    by_header = _request({"X-Portal-Internal-Token": b"internal-token-value"})
    assert require_nginx_internal_token(by_header, None, settings) == "internal-token-value"
    bearer = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials="internal-token-value"
    )
    assert require_nginx_internal_token(_request({}), bearer, settings) == "internal-token-value"


@pytest.mark.parametrize(
    "header",
    [b"", b"wrong", b"internal-token-valuX", b"internal-token-value-longer", "jeton-é".encode("latin-1")],
)
def test_require_nginx_internal_token_rejects_bad_header(header):
    settings = _token_settings()
    request = _request({"X-Portal-Internal-Token": header})
    with pytest.raises(HTTPException) as exc:
        require_nginx_internal_token(request, None, settings)
    assert exc.value.status_code == 403


def test_require_nginx_internal_token_rejects_bad_bearer_and_unconfigured():
    bearer = HTTPAuthorizationCredentials(scheme="Bearer", credentials="jeton-é")
    with pytest.raises(HTTPException) as exc:
        require_nginx_internal_token(_request({}), bearer, _token_settings())
    assert exc.value.status_code == 403
    with pytest.raises(HTTPException) as exc:
        require_nginx_internal_token(_request({}), None, _token_settings(""))
    assert exc.value.status_code == 503
