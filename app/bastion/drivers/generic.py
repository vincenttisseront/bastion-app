"""Generic robotic vault driver — HTML form login, HTTP Basic Auth, and X-WSSE."""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

import httpx

from app.bastion.bastion_fields import parse_login_extra_fields
from app.bastion.drivers.base import DriverLoginError, DriverLoginResult
from app.models import App
from app.vault.user_app_credential_service import ResolvedCredential

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0

# JSON body keys that become session cookies (grommunio-admin API, etc.)
_JSON_COOKIE_KEYS: tuple[str, ...] = (
    "grommunioAuthJwt",
    "csrf",
)

_HIDDEN_INPUT_RE = re.compile(
    r"""<input\b(?=[^>]*\btype\s*=\s*["']hidden["'])[^>]*>""",
    re.IGNORECASE,
)
_ATTR_RE = re.compile(
    r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""",
)

# Headers mirrored from the browser so apps like grommunio-web store a matching
# BrowserFingerprint (User-Agent + Accept-Language) in the PHP session.
_BROWSER_HEADER_NAMES: tuple[str, ...] = (
    "user-agent",
    "accept-language",
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


def _cookies_from_client(client: httpx.AsyncClient) -> dict[str, str]:
    """All cookies accumulated in the client jar (GET + POST)."""
    return {name: value for name, value in client.cookies.items() if value}


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


def extract_hidden_form_fields(html: str) -> dict[str, str]:
    """Extract ``<input type="hidden" name=… value=…>`` pairs (CSRF tokens, etc.)."""
    out: dict[str, str] = {}
    for tag in _HIDDEN_INPUT_RE.findall(html or ""):
        attrs: dict[str, str] = {}
        for match in _ATTR_RE.finditer(tag):
            key = match.group(1).lower()
            attrs[key] = match.group(2) or match.group(3) or match.group(4) or ""
        name = attrs.get("name")
        if name:
            out[name] = attrs.get("value", "")
    return out


def _path_is_spa_login(login_url: str) -> bool:
    path = (urlparse(login_url).path or "").rstrip("/") or "/"
    return path == "/login" or path.endswith("/login")


def _grommunio_admin_api_url(login_url: str) -> str:
    """Map SPA /login → POST /api/v1/login (grommunio-admin)."""
    parsed = urlparse(login_url)
    return urlunparse(parsed._replace(path="/api/v1/login", query="", fragment=""))


def _login_page_url(login_url: str) -> str:
    """URL to GET for session/CSRF bootstrap (strip query like ``?logon``)."""
    parsed = urlparse(login_url)
    return urlunparse(parsed._replace(query="", fragment=""))


def _safe_url_for_log(url: str) -> str:
    """Strip query string that might contain secrets."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))


def _browser_headers(client_headers: dict[str, str] | None) -> dict[str, str]:
    if not client_headers:
        return {}
    out: dict[str, str] = {}
    for key, value in client_headers.items():
        if key.lower() in _BROWSER_HEADER_NAMES and value:
            # Preserve canonical header names for httpx
            if key.lower() == "user-agent":
                out["User-Agent"] = value
            elif key.lower() == "accept-language":
                out["Accept-Language"] = value
    return out


def _looks_like_login_html(body: str) -> bool:
    sample = body[:12000] if body else ""
    if 'name="password"' not in sample and "name='password'" not in sample:
        return False
    return (
        "?logon" in sample
        or 'name="username"' in sample
        or "name='username'" in sample
        or 'id="username"' in sample
    )


def _grommunio_hresult_failed(response: httpx.Response) -> bool:
    hresult = (response.headers.get("x-grommunio-hresult") or "").strip()
    if not hresult:
        return False
    return hresult.upper() not in ("NOERROR", "0", "S_OK")


def _is_auth_failure(response: httpx.Response) -> bool:
    if response.status_code in (401, 403):
        return True
    if _grommunio_hresult_failed(response):
        return True
    if response.status_code == 200 and _looks_like_login_html(response.text or ""):
        return True
    return False


def _is_auth_success(response: httpx.Response) -> bool:
    if response.status_code in (301, 302, 303, 307, 308):
        return not _grommunio_hresult_failed(response)
    if response.status_code == 200 and not _is_auth_failure(response):
        return True
    return False


async def generic_form_login(
    credential: ResolvedCredential | object,
    app: App,
    password: str,
    *,
    client_headers: dict[str, str] | None = None,
) -> DriverLoginResult:
    """
    POST/GET login form with vault credentials; return session cookies.

    For HTML form apps (e.g. grommunio-web):
      1. GET the login page (same httpx session) to obtain session/CSRF cookies
         and any hidden form fields.
      2. POST credentials + hidden fields with the browser's User-Agent /
         Accept-Language so PHP BrowserFingerprint matches the real user.
      3. Treat 303/redirect or non-login HTML as success; X-grommunio-Hresult
         or a redisplayed login form as auth rejection (never treat bare
         Set-Cookie on a failed login page as success).

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

    headers = _browser_headers(client_headers)
    log_url = _safe_url_for_log(login_url)

    def _payload(uf: str, pf: str, hidden: dict[str, str] | None = None) -> dict[str, str]:
        body = dict(extra)
        if hidden:
            body.update(hidden)
        body[uf] = _username(credential)
        body[pf] = password
        return body

    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT,
            follow_redirects=False,
            headers=headers or None,
        ) as client:
            hidden_fields: dict[str, str] = {}
            if method == "POST" and not _path_is_spa_login(login_url):
                page_url = _login_page_url(login_url)
                logger.info("generic_form bootstrap GET %s", _safe_url_for_log(page_url))
                bootstrap = await client.get(page_url)
                if bootstrap.status_code >= 500:
                    raise DriverUpstreamError(
                        f"Upstream login page returned HTTP {bootstrap.status_code}"
                    )
                if 200 <= bootstrap.status_code < 400:
                    hidden_fields = extract_hidden_form_fields(bootstrap.text or "")
                    if hidden_fields:
                        logger.info(
                            "generic_form: extracted hidden fields %s",
                            sorted(hidden_fields.keys()),
                        )

            if method == "GET":
                response = await client.get(
                    login_url, params=_payload(username_field, password_field, hidden_fields)
                )
            else:
                response = await client.post(
                    login_url,
                    data=_payload(username_field, password_field, hidden_fields),
                    headers={
                        **headers,
                        "Referer": _login_page_url(login_url),
                        "Origin": f"{urlparse(login_url).scheme}://{urlparse(login_url).netloc}",
                    },
                )
                # grommunio-admin SPA: GET /login is HTML, POST → 405; real API is /api/v1/login
                if response.status_code == 405 and _path_is_spa_login(login_url):
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
                        login_url,
                        data=_payload(username_field, password_field),
                    )

            status = response.status_code
            logger.info("generic_form login url=%s status=%s", log_url, status)

            if status in (404, 405) or status >= 500:
                allow = response.headers.get("allow", "")
                logger.warning(
                    "generic_form upstream technical error url=%s status=%s allow=%s",
                    log_url,
                    status,
                    allow or "-",
                )
                raise DriverUpstreamError(f"Upstream returned HTTP {status}")

            if _is_auth_failure(response):
                hresult = response.headers.get("x-grommunio-hresult", "")
                logger.info(
                    "generic_form auth rejected url=%s status=%s hresult=%s",
                    log_url,
                    status,
                    hresult or "-",
                )
                raise DriverAuthRejectedError("Upstream rejected credentials")

            if not _is_auth_success(response):
                raise DriverUpstreamError(f"Upstream returned unexpected HTTP {status}")

            cookies = _cookies_from_client(client)
            if not cookies:
                cookies = _extract_response_cookies(response)
            if not cookies:
                cookies = _cookies_from_json_body(response)

            if not cookies:
                raise DriverAuthRejectedError("Upstream returned no session cookies")

            return DriverLoginResult(cookies=cookies)
    except httpx.TimeoutException as exc:
        logger.warning("generic_form login timeout url=%s", log_url)
        raise DriverUpstreamError("Generic form login timed out") from exc
    except httpx.RequestError as exc:
        logger.warning("generic_form login network error url=%s", log_url)
        raise DriverUpstreamError("Generic form login network error") from exc
    finally:
        password = ""  # noqa: F841


def generic_basic_auth_header(credential: ResolvedCredential | object, password: str) -> str:
    """
    Build Authorization header value for HTTP Basic Auth.

    Never log the return value.
    """
    token = base64.b64encode(
        f"{_username(credential)}:{password}".encode("utf-8")
    ).decode("ascii")
    return f"Basic {token}"


def generic_wsse_header(
    username: str,
    password: str,
    *,
    nonce: bytes | None = None,
    created: str | None = None,
) -> str:
    """
    Build a fresh X-WSSE UsernameToken header value (without the ``X-WSSE:`` prefix).

    MUST be called anew for every outgoing request — never cache/memoize the result.
    A reused nonce/Created would look like a replay attack to the target app.

    SHA-1 is mandated by the WSSE UsernameToken profile itself (legacy protocol
    constraint, not an application security choice). Do not "upgrade" the digest
    algorithm without confirming the target API supports an alternate profile.

    Never log ``password`` or the raw digest input.
    """
    nonce_bytes = nonce if nonce is not None else secrets.token_bytes(16)
    nonce_b64 = base64.b64encode(nonce_bytes).decode("ascii")
    created_ts = created or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Digest input: raw nonce bytes + created (UTF-8) + password (UTF-8) — NOT nonce_b64.
    digest_input = nonce_bytes + created_ts.encode("utf-8") + password.encode("utf-8")
    digest = base64.b64encode(hashlib.sha1(digest_input).digest()).decode("ascii")  # noqa: S324
    return (
        f'UsernameToken Username="{username}", PasswordDigest="{digest}", '
        f'Nonce="{nonce_b64}", Created="{created_ts}"'
    )


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


async def generic_wsse_probe(
    app: App,
    username: str,
    password: str,
) -> bool:
    """HEAD/GET upstream with a fresh X-WSSE header; success = not 401/403."""
    url = (app.upstream_url or "").strip()
    if not url:
        return False
    wsse = generic_wsse_header(username, password)
    headers = {
        "X-WSSE": wsse,
        "Authorization": 'WSSE profile="UsernameToken"',
    }
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as client:
            response = await client.head(url, headers=headers)
            if response.status_code == 405:
                response = await client.get(url, headers=headers)
    except httpx.RequestError:
        return False
    return response.status_code not in (401, 403)
