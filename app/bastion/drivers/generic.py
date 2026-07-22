"""Generic robotic vault driver — HTML form login and HTTP Basic Auth."""

from __future__ import annotations

import base64
import logging
from urllib.parse import urlparse, urlunparse

import httpx

from app.bastion.bastion_fields import parse_login_extra_fields
from app.bastion.drivers.base import DriverLoginError, DriverLoginResult
from app.models import App
from app.vault.user_app_credential_service import ResolvedCredential

logger = logging.getLogger(__name__)

_TIMEOUT = 5.0

# JSON body keys that become session cookies (grommunio-admin API, etc.)
_JSON_COOKIE_KEYS: tuple[str, ...] = (
    "grommunioAuthJwt",
    "csrf",
)


class DriverAuthRejectedError(DriverLoginError):
    """Upstream rejected credentials (401/403 or explicit login failure)."""


class DriverUpstreamError(DriverLoginError):
    """Misconfigured request or upstream technical failure (404/405/5xx)."""


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
    for header_value in response.headers.get_list("set-cookie"):
        part = header_value.split(";", 1)[0].strip()
        if "=" in part:
            key, val = part.split("=", 1)
            out[key.strip()] = val.strip()
    return out


def _cookies_from_json_body(response: httpx.Response) -> dict[str, str]:
    """Synthesize cookies from JSON login APIs (e.g. grommunio-admin JWT)."""
    content_type = (response.headers.get("content-type") or "").lower()
    if "json" not in content_type:
        return {}
    try:
        payload = response.json()
    except ValueError:
        return {}
    if not isinstance(payload, dict):
        return {}
    out: dict[str, str] = {}
    for key in _JSON_COOKIE_KEYS:
        value = payload.get(key)
        if value is not None and str(value).strip():
            out[key] = str(value)
    return out


def _path_is_spa_login(login_url: str) -> bool:
    path = (urlparse(login_url).path or "").rstrip("/") or "/"
    return path == "/login" or path.endswith("/login")


def _grommunio_admin_api_url(login_url: str) -> str:
    """Map SPA /login → POST /api/v1/login (grommunio-admin)."""
    parsed = urlparse(login_url)
    return urlunparse(parsed._replace(path="/api/v1/login", query="", fragment=""))


def _safe_url_for_log(url: str) -> str:
    """Strip query string that might contain secrets."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))


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
        raise DriverUpstreamError("Login form URL is not configured")

    username_field = (app.login_username_field or "username").strip() or "username"
    password_field = (app.login_password_field or "password").strip() or "password"
    method = (app.login_http_method or "POST").strip().upper()
    if method not in ("POST", "GET"):
        raise DriverUpstreamError("Invalid login HTTP method")

    extra: dict[str, str] = {}
    try:
        extra.update(parse_login_extra_fields(app.login_extra_fields))
    except ValueError as exc:
        raise DriverUpstreamError("Invalid login extra fields JSON") from exc

    def _payload(uf: str, pf: str) -> dict[str, str]:
        body = dict(extra)
        body[uf] = _username(credential)
        body[pf] = password
        return body

    log_url = _safe_url_for_log(login_url)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as client:
            if method == "GET":
                response = await client.get(login_url, params=_payload(username_field, password_field))
            else:
                response = await client.post(
                    login_url, data=_payload(username_field, password_field)
                )
                # grommunio-admin SPA: GET /login is HTML, POST → 405; real API is /api/v1/login
                if (
                    response.status_code == 405
                    and _path_is_spa_login(login_url)
                ):
                    api_url = _grommunio_admin_api_url(login_url)
                    logger.info(
                        "generic_form: SPA POST 405 on %s — retrying %s (user/pass)",
                        log_url,
                        _safe_url_for_log(api_url),
                    )
                    login_url = api_url
                    log_url = _safe_url_for_log(login_url)
                    username_field, password_field = "user", "pass"
                    response = await client.post(
                        login_url, data=_payload(username_field, password_field)
                    )
    except httpx.TimeoutException as exc:
        logger.warning("generic_form login timeout url=%s", log_url)
        raise DriverUpstreamError("Generic form login timed out") from exc
    except httpx.RequestError as exc:
        logger.warning("generic_form login network error url=%s", log_url)
        raise DriverUpstreamError("Generic form login network error") from exc
    finally:
        password = ""  # noqa: F841

    status = response.status_code
    logger.info("generic_form login url=%s status=%s", log_url, status)

    if status in (401, 403):
        raise DriverAuthRejectedError("Upstream rejected credentials")

    if status in (404, 405) or status >= 500:
        allow = response.headers.get("allow", "")
        logger.warning(
            "generic_form upstream technical error url=%s status=%s allow=%s",
            log_url,
            status,
            allow or "-",
        )
        raise DriverUpstreamError(f"Upstream returned HTTP {status}")

    cookies = _extract_response_cookies(response)
    if not cookies:
        cookies = _cookies_from_json_body(response)

    if not cookies:
        # 2xx/3xx without session usually means form redisplay = bad credentials
        if 200 <= status < 400:
            raise DriverAuthRejectedError("Upstream returned no session cookies")
        raise DriverUpstreamError(f"Upstream returned HTTP {status} without session")

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
