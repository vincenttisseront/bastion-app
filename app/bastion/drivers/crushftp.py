"""CrushFTP robotic SSO driver — login via WebInterface function API."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from app.bastion.drivers.base import RoboticDriver, RoboticLoginError

logger = logging.getLogger(__name__)

_TIMEOUT = 5.0
_SUCCESS_RE = re.compile(r"<response>\s*success\s*</response>", re.IGNORECASE)
_USERNAME_RE = re.compile(
    r"<response>\s*(?:<!\[CDATA\[)?\s*([^<\]]+?)\s*(?:\]\]>)?\s*</response>",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CrushFTPSession:
    """Structured CrushFTP session cookies (not a framework cookie jar)."""

    cookies: dict[str, str]
    base_url: str


def _normalize_base_url(base_url: str) -> str:
    return base_url.rstrip("/") + "/"


def _extract_session_cookies(response: httpx.Response) -> dict[str, str]:
    out: dict[str, str] = {}
    crush_auth = response.cookies.get("CrushAuth")
    current_auth = response.cookies.get("currentAuth")
    if crush_auth:
        out["CrushAuth"] = crush_auth
    if current_auth:
        out["currentAuth"] = current_auth
    # Some CrushFTP builds only set CrushAuth; derive currentAuth as last 4 chars.
    if "CrushAuth" in out and "currentAuth" not in out and len(out["CrushAuth"]) >= 4:
        out["currentAuth"] = out["CrushAuth"][-4:]
    return out


def _c2f(cookies: dict[str, str]) -> str | None:
    if "currentAuth" in cookies:
        return cookies["currentAuth"]
    crush = cookies.get("CrushAuth")
    if crush and len(crush) >= 4:
        return crush[-4:]
    return None


class CrushFTPDriver(RoboticDriver):
    """Robotic login against CrushFTP `/WebInterface/function/`."""

    async def login(self, base_url: str, username: str, password: str) -> CrushFTPSession:
        base = _normalize_base_url(base_url)
        url = urljoin(base, "WebInterface/function/")
        data = {
            "command": "login",
            "username": username,
            "password": password,
            "encoded": "true",
            "language": "en",
        }
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as client:
                response = await client.post(url, data=data)
        except httpx.TimeoutException as exc:
            raise RoboticLoginError("CrushFTP login timed out") from exc
        except httpx.RequestError as exc:
            raise RoboticLoginError("CrushFTP login network error") from exc

        if not _SUCCESS_RE.search(response.text or ""):
            raise RoboticLoginError("CrushFTP login rejected")

        cookies = _extract_session_cookies(response)
        if "CrushAuth" not in cookies:
            raise RoboticLoginError("CrushFTP login missing CrushAuth cookie")

        return CrushFTPSession(cookies=cookies, base_url=base)

    async def get_username(self, session: CrushFTPSession) -> str:
        url = urljoin(session.base_url, "WebInterface/function/")
        c2f = _c2f(session.cookies)
        if not c2f:
            raise RoboticLoginError("CrushFTP session missing auth token")
        data = {"command": "getUsername", "c2f": c2f}
        headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in session.cookies.items())}
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as client:
                response = await client.post(url, data=data, headers=headers)
        except httpx.TimeoutException as exc:
            raise RoboticLoginError("CrushFTP getUsername timed out") from exc
        except httpx.RequestError as exc:
            raise RoboticLoginError("CrushFTP getUsername network error") from exc

        match = _USERNAME_RE.search(response.text or "")
        if not match:
            raise RoboticLoginError("CrushFTP getUsername returned no identity")
        username = match.group(1).strip()
        if not username or username.lower() in ("failure", "error", "anonymous"):
            raise RoboticLoginError("CrushFTP getUsername identity check failed")
        return username

    async def fingerprint(self, base_url: str) -> bool:
        base = _normalize_base_url(base_url)
        url = urljoin(base, "WebInterface/login.html")
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
                response = await client.get(url)
        except httpx.RequestError:
            return False
        body = (response.text or "").lower()
        return "crushftp" in body or "webinterface" in response.url.path.lower()
