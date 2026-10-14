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


_DEV_SIGNING_SECRET = "dev-insecure"


def portal_signing_secret(settings) -> str:
    """HMAC key for portal cookies (CSRF tokens, flash messages, one-shot reveals).

    Outside production an empty ``VAULT_PORTAL_INTERNAL_TOKEN`` falls back to a
    public constant; in production that would make every signed cookie forgeable.
    """
    secret = (settings.vault_portal_internal_token or "").strip()
    if secret:
        return secret
    if getattr(settings, "is_production", False):
        raise RuntimeError("VAULT_PORTAL_INTERNAL_TOKEN is required in production")
    return _DEV_SIGNING_SECRET


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


_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_TRUSTED_FETCH_SITES = frozenset({"same-origin", "none"})
# nginx-internal subrequests (auth_request, unknown-host catch-all) are never browser-initiated.
_EXEMPT_PREFIXES = ("/internal/",)


def _header(scope: Scope, name: bytes) -> str:
    for key, value in scope.get("headers") or ():
        if key == name:
            return value.decode("latin-1").strip()
    return ""


def _host_of(origin: str) -> str:
    _, _, rest = origin.partition("://")
    return rest.split("/", 1)[0].lower()


def is_cross_origin_browser_write(scope: Scope) -> bool:
    """True for a cookie-carrying unsafe request a browser flagged as not same-origin.

    Sibling subdomains are *same-site*, so ``SameSite=Lax`` cookies reach the portal
    from them; Fetch Metadata (or ``Origin`` on older browsers) tells them apart.
    Non-browser clients send neither header and are left to their own auth.
    """
    if scope.get("method", "GET").upper() not in _UNSAFE_METHODS:
        return False
    if scope.get("path", "").startswith(_EXEMPT_PREFIXES):
        return False
    if not _header(scope, b"cookie") or _header(scope, b"authorization"):
        return False
    site = _header(scope, b"sec-fetch-site").lower()
    if site:
        return site not in _TRUSTED_FETCH_SITES
    origin = _header(scope, b"origin")
    if not origin:
        return False
    hosts = {
        h.strip().lower()
        for h in (_header(scope, b"host"), *_header(scope, b"x-forwarded-host").split(","))
        if h.strip()
    }
    return origin == "null" or _host_of(origin) not in hosts


class CrossOriginWriteMiddleware:
    """Reject cross-origin browser writes before any route runs (CSRF baseline).

    Complements per-form ``csrf_token`` checks: it covers every admin / API route,
    including the many forms and ``fetch`` calls that carry no token.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and is_cross_origin_browser_write(scope):
            body = b'{"detail":"Cross-origin request blocked"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


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
