"""Signed ``bastion_mfa_ok`` cookie — proves admin passed second-factor for this session.

Bound to ``user_email`` + expiry; HMAC via ``portal_signing_secret``.
Independent of oauth2-proxy identity headers (which are not mutable).

Flags match portal session cookies (HttpOnly + Secure + SameSite=Lax) so logout
can expire the cookie reliably; host-only (no Domain) — admin is portal-host.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from urllib.parse import quote

from fastapi import Request, Response

from app.web.csrf import portal_signing_secret

MFA_COOKIE_NAME = "bastion_mfa_ok"
MFA_TTL_SECONDS = 8 * 3600  # 8h work session

_MFA_COOKIE_FLAGS = {
    "httponly": True,
    "secure": True,
    "samesite": "lax",
    "path": "/",
}


def _normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def generate_mfa_signature(secret: str, user_email: str, expires_at: int) -> str:
    message = f"{_normalize_email(user_email)}:{expires_at}".encode("utf-8")
    return hmac.new(
        secret.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()


def set_mfa_ok_cookie(
    response: Response,
    settings,
    user_email: str,
    *,
    ttl_seconds: int = MFA_TTL_SECONDS,
) -> None:
    email = _normalize_email(user_email)
    if not email:
        return
    expires_at = int(time.time()) + int(ttl_seconds)
    secret = portal_signing_secret(settings)
    signature = generate_mfa_signature(secret, email, expires_at)
    value = f"{email}|{expires_at}|{signature}"
    response.set_cookie(
        key=MFA_COOKIE_NAME,
        value=value,
        max_age=int(ttl_seconds),
        **_MFA_COOKIE_FLAGS,
    )


def clear_mfa_ok_cookie(response: Response) -> None:
    """Expire MFA cookie with the same flags used at set time."""
    response.delete_cookie(key=MFA_COOKIE_NAME, **_MFA_COOKIE_FLAGS)


def is_mfa_cookie_valid(request: Request, settings, expected_email: str) -> bool:
    cookie = (request.cookies.get(MFA_COOKIE_NAME) or "").strip()
    if not cookie:
        return False
    try:
        email, expires_at_str, signature = cookie.split("|", 2)
    except ValueError:
        return False
    expected = _normalize_email(expected_email)
    if _normalize_email(email) != expected:
        return False
    try:
        expires_at = int(expires_at_str)
    except ValueError:
        return False
    if time.time() > expires_at:
        return False
    secret = portal_signing_secret(settings)
    expected_sig = generate_mfa_signature(secret, email, expires_at)
    return hmac.compare_digest(signature, expected_sig)


def challenge_redirect_url(next_path: str) -> str:
    target = (next_path or "/admin").strip() or "/admin"
    if not target.startswith("/") or target.startswith("//"):
        target = "/admin"
    return f"/admin/auth/mfa/challenge?next={quote(target, safe='/?&=')}"
