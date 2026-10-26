"""Admin MFA gate — challenge cookie + grace / forced enrollment."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Request
from sqlalchemy.orm import Session

from app.auth.mfa_cookie import challenge_redirect_url, is_mfa_cookie_valid
from app.models import AdminMfaCredential
from app.sso_settings import Settings
from app.web.user_context import UserContext

# Paths that must remain reachable without ``mfa_ok`` (avoid redirect loops).
_MFA_EXEMPT_PREFIXES = (
    "/admin/auth/mfa/",
    "/admin/profile",
)

ENROLLMENT_REDIRECT = "/admin/profile?force_mfa=1#mfa"


class MfaChallengeRequired(Exception):
    """Admin has MFA enabled but has not completed the challenge this session."""

    def __init__(self, redirect_url: str):
        self.redirect_url = redirect_url
        super().__init__(redirect_url)


class MfaEnrollmentRequired(Exception):
    """Global enforcement past grace — admin must enroll a factor."""

    def __init__(self, redirect_url: str = ENROLLMENT_REDIRECT):
        self.redirect_url = redirect_url
        super().__init__(redirect_url)


def path_is_mfa_exempt(path: str) -> bool:
    p = (path or "").split("?", 1)[0]
    return any(
        p == pref.rstrip("/") or p.startswith(pref) for pref in _MFA_EXEMPT_PREFIXES
    )


def is_mfa_enrolled(db: Session, user_email: str) -> bool:
    email = (user_email or "").strip().lower()
    if not email:
        return False
    row = (
        db.query(AdminMfaCredential)
        .filter(AdminMfaCredential.user_email == email)
        .first()
    )
    return bool(row and (row.totp_enabled or row.webauthn_enabled))


def enforcement_deadline(settings: Settings) -> datetime | None:
    pivot = getattr(settings, "mfa_enforcement_pivot_date", None)
    if pivot is None:
        return None
    days = int(getattr(settings, "mfa_enforcement_grace_days", 7) or 0)
    if pivot.tzinfo is None:
        pivot = pivot.replace(tzinfo=timezone.utc)
    return pivot + timedelta(days=days)


def grace_days_left(settings: Settings, *, now: datetime | None = None) -> int | None:
    """Days remaining in grace (inclusive). None if enforcement off / no pivot."""
    if not getattr(settings, "mfa_enforcement_required", False):
        return None
    deadline = enforcement_deadline(settings)
    if deadline is None:
        return None
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    delta = deadline - now
    # ceil-ish: still show 1 day on the last calendar day
    return max(0, delta.days + (1 if delta.seconds or delta.microseconds else 0))


def apply_grace_banner(request: Request, settings: Settings, enrolled: bool) -> None:
    if enrolled:
        return
    if not getattr(settings, "mfa_enforcement_required", False):
        return
    left = grace_days_left(settings)
    if left is None:
        return
    deadline = enforcement_deadline(settings)
    now = datetime.now(timezone.utc)
    if deadline is not None and now > deadline:
        return
    if left <= 0:
        return
    request.state.mfa_grace_warning = (
        f"Enrôlement MFA obligatoire dans {left} jour(s)."
    )


def enforce_admin_mfa(
    request: Request,
    user: UserContext,
    db: Session,
    settings: Settings,
) -> None:
    """Gate admin routes: MFA cookie, grace banner, or forced enrollment.

    Break-glass sessions skip MFA (emergency unlock path).
    """
    if getattr(user, "is_breakglass", False) or getattr(
        user, "auth_source", ""
    ) == "breakglass":
        return
    if path_is_mfa_exempt(request.url.path):
        return

    email = (user.email or "").strip()
    if not email:
        return

    enrolled = is_mfa_enrolled(db, email)

    if enrolled:
        if is_mfa_cookie_valid(request, settings, email):
            return
        next_path = request.url.path
        if request.url.query:
            next_path = f"{next_path}?{request.url.query}"
        raise MfaChallengeRequired(challenge_redirect_url(next_path))

    # Not enrolled
    apply_grace_banner(request, settings, enrolled=False)

    if not getattr(settings, "mfa_enforcement_required", False):
        return

    deadline = enforcement_deadline(settings)
    if deadline is None:
        # Flag on but no pivot → treat as soft banner only (already applied if pivot set)
        return

    now = datetime.now(timezone.utc)
    if now > deadline:
        raise MfaEnrollmentRequired(ENROLLMENT_REDIRECT)
