"""Session-independent CSRF protection (signed double-submit cookie).

Each browser gets a random ``bastion_csrf`` nonce cookie; form tokens are an
HMAC of that nonce. A cross-site attacker can neither read the nonce nor mint
a matching token, including on anonymous pages such as ``/auth/login``.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from http.cookies import SimpleCookie

from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

CSRF_COOKIE = "bastion_csrf"
_STATE_KEY = "csrf_nonce"
_NONCE_BYTES = 32


def _cookie_from_scope(scope: Scope) -> str:
    for name, value in scope.get("headers") or ():
        if name == b"cookie":
            jar = SimpleCookie()
            try:
                jar.load(value.decode("latin-1"))
            except Exception:
                return ""
            morsel = jar.get(CSRF_COOKIE)
            if morsel and morsel.value:
                return morsel.value
    return ""


def _is_html(headers: list[tuple[bytes, bytes]]) -> bool:
    """Only pages can carry a form token; static/API responses must stay cacheable."""
    return any(
        name.lower() == b"content-type" and value.lower().startswith(b"text/html")
        for name, value in headers
    )


def _nonce(request: Request) -> str:
    return getattr(request.state, _STATE_KEY, "") or request.cookies.get(CSRF_COOKIE, "")


def csrf_secret(settings) -> str:
    """HMAC key shared by every page that renders or checks a form token."""
    return settings.vault_portal_internal_token or "dev-insecure"


def make_csrf_token(request: Request, secret: str) -> str:
    """Form / header token bound to this browser's CSRF nonce."""
    if not secret:
        raise RuntimeError("CSRF secret is empty")
    nonce = _nonce(request)
    return hmac.new(secret.encode(), f"csrf:{nonce}".encode(), hashlib.sha256).hexdigest()


def verify_csrf_token(request: Request, secret: str, csrf_token: str = "") -> bool:
    """Validate form ``csrf_token`` or ``X-CSRF-Token`` against the request nonce."""
    if not request.cookies.get(CSRF_COOKIE):
        return False
    expected = make_csrf_token(request, secret)
    candidates = (
        (csrf_token or "").strip(),
        (request.headers.get("X-CSRF-Token") or "").strip(),
    )
    return any(c and hmac.compare_digest(c, expected) for c in candidates)


class CsrfCookieMiddleware:
    """Issue the ``bastion_csrf`` nonce on the first HTTP response that lacks it."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or _cookie_from_scope(scope):
            await self.app(scope, receive, send)
            return

        nonce = secrets.token_urlsafe(_NONCE_BYTES)
        scope.setdefault("state", {})[_STATE_KEY] = nonce
        cookie = (
            f"{CSRF_COOKIE}={nonce}; Path=/; HttpOnly; Secure; SameSite=Strict"
        ).encode("latin-1")

        async def send_with_cookie(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                if _is_html(headers):
                    headers.append((b"set-cookie", cookie))
                    message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_cookie)
