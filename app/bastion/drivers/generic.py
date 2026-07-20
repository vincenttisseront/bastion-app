"""Generic robotic vault driver — HTML form login and HTTP Basic Auth."""

from __future__ import annotations

import base64
import logging

import httpx

from app.bastion.bastion_fields import parse_login_extra_fields
from app.bastion.drivers.base import DriverLoginError, DriverLoginResult
from app.models import App
from app.vault.user_app_credential_service import ResolvedCredential

logger = logging.getLogger(__name__)

_TIMEOUT = 5.0


def _username(credential: ResolvedCredential | object) -> str:
    return str(getattr(credential, "robotic_username", "") or "")


def _extract_response_cookies(response: httpx.Response) -> dict[str, str]:
    """Collect all Set-Cookie values from the response."""
    out: dict[str, str] = {}
    for name, value in response.cookies.items():
        if value:
            out[name] = value
    if out:
        return out
    # Fallback: parse raw set-cookie headers when jar is empty.
    for header_value in response.headers.get_list("set-cookie"):
        part = header_value.split(";", 1)[0].strip()
        if "=" in part:
            key, val = part.split("=", 1)
            out[key.strip()] = val.strip()
    return out


async def generic_form_login(
    credential: ResolvedCredential | object,
    app: App,
    password: str,
) -> DriverLoginResult:
    """
    POST/GET login form with vault credentials; return session cookies.

    Never logs or returns the plaintext password.
    """
    login_url = (app.login_form_url or "").strip()
    if not login_url:
        raise DriverLoginError("Login form URL is not configured")

    username_field = (app.login_username_field or "username").strip() or "username"
    password_field = (app.login_password_field or "password").strip() or "password"
    method = (app.login_http_method or "POST").strip().upper()
    if method not in ("POST", "GET"):
        raise DriverLoginError("Invalid login HTTP method")

    payload: dict[str, str] = {}
    try:
        payload.update(parse_login_extra_fields(app.login_extra_fields))
    except ValueError as exc:
        raise DriverLoginError("Invalid login extra fields JSON") from exc
    payload[username_field] = _username(credential)
    payload[password_field] = password

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as client:
            if method == "GET":
                response = await client.get(login_url, params=payload)
            else:
                response = await client.post(login_url, data=payload)
    except httpx.TimeoutException as exc:
        raise DriverLoginError("Generic form login timed out") from exc
    except httpx.RequestError as exc:
        raise DriverLoginError("Generic form login network error") from exc

    cookies = _extract_response_cookies(response)
    if not cookies:
        raise DriverLoginError("Generic form login returned no session cookies")

    return DriverLoginResult(cookies=cookies)


def generic_basic_auth_header(credential: ResolvedCredential | object, password: str) -> str:
    """
    Build Authorization header value for HTTP Basic Auth.

    Never log the return value.
    """
    token = base64.b64encode(
        f"{_username(credential)}:{password}".encode("utf-8")
    ).decode("ascii")
    return f"Basic {token}"


async def generic_basic_auth_probe(
    app: App,
    auth_header: str,
) -> bool:
    """HEAD/GET upstream with Basic Auth; success = not 401/403."""
    url = (app.upstream_url or "").strip()
    if not url:
        return False
    headers = {"Authorization": auth_header}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as client:
            response = await client.head(url, headers=headers)
            if response.status_code == 405:
                response = await client.get(url, headers=headers)
    except httpx.RequestError:
        return False
    return response.status_code not in (401, 403)
