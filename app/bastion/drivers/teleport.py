"""Teleport robotic SSO — web session via /v1/webapi/sessions/web (JSON API)."""

from __future__ import annotations

import binascii
import json
import logging
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from app.bastion.drivers.base import RoboticDriver, RoboticLoginError

logger = logging.getLogger(__name__)

_TIMEOUT = 15.0
_SESSION_PATH = "/v1/webapi/sessions/web"
_USER_STATUS_PATH = "/webapi/user/status"
_PING_PATHS = ("/v1/webapi/ping", "/webapi/ping")

# Teleport web session cookie (v13+): hex(JSON {user,sid}) — see lib/web/session/cookie.go.
# CSRF is separate: __Host-grv_csrf (lib/httplib/csrf/csrf.go).
_SESSION_COOKIE_NAMES = (
    "__Host-session",
    "__Secure-session",
)
_CSRF_COOKIE_NAMES = (
    "__Host-grv_csrf",
    "__Secure-grv_csrf",
)
# Legacy / mistaken names — never inject; cleared on hop when present.
_STALE_SESSION_COOKIE_NAMES = (
    "__Host-grv_session",
    "__Secure-grv_session",
    "grv_session",
    "_teleport_session",
)


@dataclass(frozen=True)
class TeleportSession:
    cookies: dict[str, str]
    base_url: str
    tls_verify: bool = False
    username: str | None = None
    bearer_token: str | None = None
    # Host/Origin/Referer when login hits upstream IP but browser uses public_fqdn.
    request_headers: dict[str, str] | None = None


def _normalize_base_url(base_url: str) -> str:
    return (base_url or "").strip().rstrip("/")


def _session_api_url(base_url: str) -> str:
    return urljoin(_normalize_base_url(base_url) + "/", _SESSION_PATH.lstrip("/"))


def _extract_session_cookies(response: httpx.Response) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in _SESSION_COOKIE_NAMES:
        value = response.cookies.get(name)
        if value:
            out[name] = value
    for name in _CSRF_COOKIE_NAMES:
        value = response.cookies.get(name)
        if value:
            out[name] = value
    if out:
        return out
    # Do not map JSON bearer token to a browser cookie — it is not __Host-session.
    return out


def stale_teleport_browser_cookies() -> tuple[str, ...]:
    """Cookie names to expire on the app FQDN after a successful Teleport hop."""
    return _STALE_SESSION_COOKIE_NAMES


def _extract_bearer_token(response: httpx.Response) -> str | None:
    try:
        payload = response.json()
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    token = payload.get("token")
    if isinstance(token, str) and token.strip():
        return token.strip()
    return None


def _decode_session_cookie_user(cookies: dict[str, str]) -> str | None:
    """Decode Teleport ``__Host-session`` hex(JSON {user,sid}) → username."""
    for name in _SESSION_COOKIE_NAMES:
        raw = cookies.get(name)
        if not raw:
            continue
        try:
            payload = json.loads(binascii.unhexlify(raw).decode())
        except (ValueError, json.JSONDecodeError, binascii.Error):
            continue
        if not isinstance(payload, dict):
            continue
        user = payload.get("user")
        if isinstance(user, str) and user.strip():
            return user.strip()
    return None


def _login_reject_hint(text: str, status: int) -> str:
    body = (text or "").strip()
    if not body:
        return f"réponse vide (HTTP {status})"
    lowered = body.lower()
    if "second factor" in lowered or "second_factor" in lowered:
        return (
            "Teleport exige encore un second facteur (MFA/TOTP) — "
            "désactivez-le pour ce compte vault ou utilisez un compte sans MFA"
        )
    if status in (401, 403) or "access denied" in lowered or "invalid username" in lowered:
        return (
            f"identifiants refusés (HTTP {status}) — "
            "vérifiez le credential vault ou le compte Teleport local"
        )
    if "mfa" in lowered or "otp" in lowered or "totp" in lowered:
        return (
            "Teleport exige encore un second facteur (MFA/TOTP) — "
            "désactivez-le pour ce compte vault ou utilisez un compte sans MFA"
        )
    if "<html" in lowered or "<!doctype" in lowered:
        return (
            f"réponse HTML (HTTP {status}) — l'URL pointe vers un portail SSO "
            "ou une page web, pas l'API Teleport. Utilisez l'upstream_url interne "
            "(ex. https://10.x.x.x:3080), pas le FQDN public bastion."
        )
    try:
        payload = json.loads(body)
        if isinstance(payload, dict):
            err = payload.get("error") or payload.get("message")
            if isinstance(err, dict):
                err = err.get("message") or err.get("code")
            if err:
                return f"Teleport: {err} (HTTP {status})"
    except (json.JSONDecodeError, TypeError):
        pass
    return f"pas de cookie session Teleport (HTTP {status}, {len(body)} octets)"


class TeleportDriver(RoboticDriver):
    """Robotic login against Teleport ``POST /v1/webapi/sessions/web``."""

    async def login(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        tls_verify: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> TeleportSession:
        base = _normalize_base_url(base_url)
        url = _session_api_url(base)
        payload = {
            "user": username or "",
            "pass": password or "",
            "second_factor_token": "",
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT,
                follow_redirects=False,
                verify=tls_verify,
            ) as client:
                response = await client.post(url, json=payload, headers=headers)
        except httpx.TimeoutException as exc:
            raise RoboticLoginError("Teleport login timed out") from exc
        except httpx.RequestError as exc:
            raise RoboticLoginError("Teleport login network error") from exc

        if response.status_code in (301, 302, 303, 307, 308):
            loc = response.headers.get("location") or ""
            raise RoboticLoginError(
                "Teleport login redirected (HTTP "
                f"{response.status_code}) — upstream_url probablement publique/SSO "
                f"(tentée: {base}). Utilisez l'URL interne du proxy Teleport. "
                f"Location: {loc[:120] if loc else '—'}"
            )

        cookies = _extract_session_cookies(response)
        if not cookies and response.status_code >= 400:
            body = response.text or ""
            hint = _login_reject_hint(body, response.status_code)
            logger.warning(
                "Teleport login rejected: %s | url=%s user=%s http=%s",
                hint,
                url,
                username,
                response.status_code,
            )
            raise RoboticLoginError(f"Teleport login rejected — {hint}")

        if not cookies:
            body = response.text or ""
            hint = _login_reject_hint(body, response.status_code)
            raise RoboticLoginError(f"Teleport login rejected — {hint}")

        binding_headers = dict(extra_headers) if extra_headers else None
        bearer_token = _extract_bearer_token(response)
        return TeleportSession(
            cookies=cookies,
            base_url=base,
            tls_verify=tls_verify,
            username=username,
            bearer_token=bearer_token,
            request_headers=binding_headers,
        )

    async def get_username(self, session: TeleportSession) -> str:
        decoded = _decode_session_cookie_user(session.cookies)
        if not decoded:
            raise RoboticLoginError("Teleport session cookie missing username")

        base = _normalize_base_url(session.base_url)
        url = urljoin(base + "/", _USER_STATUS_PATH.lstrip("/"))
        headers = dict(session.request_headers or {})
        if session.bearer_token:
            headers["Authorization"] = f"Bearer {session.bearer_token}"
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT,
                verify=session.tls_verify,
            ) as client:
                response = await client.get(
                    url, cookies=session.cookies, headers=headers or None
                )
        except httpx.RequestError as exc:
            raise RoboticLoginError("Teleport user status request failed") from exc
        if response.status_code >= 400:
            raise RoboticLoginError(
                f"Teleport user status HTTP {response.status_code}"
            )
        return decoded

    async def fingerprint(self, base_url: str, *, tls_verify: bool = False) -> bool:
        base = _normalize_base_url(base_url)
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=tls_verify) as client:
                for path in _PING_PATHS:
                    url = urljoin(base + "/", path.lstrip("/"))
                    response = await client.get(url)
                    if response.status_code != 200:
                        continue
                    try:
                        payload = response.json()
                        if isinstance(payload, dict):
                            return True
                    except json.JSONDecodeError:
                        if "teleport" in (response.text or "").lower():
                            return True
                response = await client.post(
                    _session_api_url(base),
                    json={"user": "", "pass": ""},
                    headers={"Content-Type": "application/json"},
                )
                return response.status_code in (400, 401, 403)
        except httpx.RequestError:
            return False

    async def logout(self, session: TeleportSession) -> None:
        url = _session_api_url(session.base_url)
        headers = dict(session.request_headers or {})
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT,
                verify=session.tls_verify,
            ) as client:
                await client.delete(
                    url, cookies=session.cookies, headers=headers or None
                )
        except httpx.RequestError:
            logger.debug("Teleport logout failed (ignored)", exc_info=True)


def resolve_teleport_login_base_url(
    app,
    settings,
) -> str:
    """
    Internal Teleport proxy URL for server-side robotic login.

    Same constraint as CrushFTP: never POST through the public FQDN guarded by
    bastion ``auth_request`` (302/HTML/portal login).
    """
    from urllib.parse import urlparse

    fqdn = (getattr(app, "public_fqdn", None) or "").strip().lower() or None
    portal = (getattr(settings, "portal_domain", None) or "").strip().lower() or None

    def _host(url: str) -> str:
        return (urlparse(url).hostname or "").lower()

    def _is_public_edge(url: str) -> bool:
        host = _host(url)
        if not host:
            return False
        if fqdn and host == fqdn:
            return True
        if portal and host == portal:
            return True
        return False

    upstream = (getattr(app, "upstream_url", None) or "").strip().rstrip("/")
    if upstream and not _is_public_edge(upstream):
        return upstream

    raise ValueError(
        "Teleport : aucune URL interne pour le login robotique. "
        "Renseignez une upstream_url interne distincte du FQDN public "
        f"({fqdn or 'public_fqdn'}), ex. https://10.x.x.x:3080 ou http://teleport:3080."
    )
