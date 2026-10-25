"""Admin MFA gate — raised from ``require_admin`` when cookie missing."""

from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from app.auth.mfa_cookie import challenge_redirect_url, is_mfa_cookie_valid
from app.auth.totp_service import totp_enabled_for
from app.sso_settings import Settings
from app.web.user_context import UserContext

# Paths that must remain reachable without ``mfa_ok`` (avoid redirect loops).
_MFA_EXEMPT_PREFIXES = (
    "/admin/auth/mfa/",
    "/admin/profile",
)


class MfaChallengeRequired(Exception):
    """Admin has TOTP enabled but has not completed the challenge this session."""

    def __init__(self, redirect_url: str):
        self.redirect_url = redirect_url
        super().__init__(redirect_url)


def path_is_mfa_exempt(path: str) -> bool:
    p = (path or "").split("?", 1)[0]
    return any(p == pref.rstrip("/") or p.startswith(pref) for pref in _MFA_EXEMPT_PREFIXES)


def enforce_admin_mfa(
    request: Request,
    user: UserContext,
    db: Session,
    settings: Settings,
) -> None:
    """Raise ``MfaChallengeRequired`` when TOTP is on and cookie is invalid.

    Break-glass sessions skip MFA (emergency unlock path).
    """
    if getattr(user, "is_breakglass", False) or getattr(
        user, "auth_source", ""
    ) == "breakglass":
        return
    if path_is_mfa_exempt(request.url.path):
        return
    email = (user.email or "").strip()
    if not email or not totp_enabled_for(db, email):
        return
    if is_mfa_cookie_valid(request, settings, email):
        return
    next_path = request.url.path
    if request.url.query:
        next_path = f"{next_path}?{request.url.query}"
    raise MfaChallengeRequired(challenge_redirect_url(next_path))
