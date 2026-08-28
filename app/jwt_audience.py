"""JWT ``aud`` (audience) helpers for portal-issued session tokens."""

from __future__ import annotations

from app.sso_settings import Settings

DEFAULT_OIDC_SESSION_JWT_AUDIENCE = "bastion-portal"
DEFAULT_BREAKGLASS_JWT_AUDIENCE = "bastion-breakglass"


def jwt_audience_matches(
    payload: dict,
    expected: str,
    *,
    strict: bool = False,
) -> bool:
    """Return True if ``aud`` matches ``expected`` (or legacy token without ``aud``)."""
    aud = payload.get("aud")
    if aud is None or aud == "":
        return not strict
    if isinstance(aud, str):
        return aud == expected
    if isinstance(aud, list):
        return expected in aud
    return False


def resolve_oidc_session_jwt_audience(settings: Settings) -> str:
    raw = (getattr(settings, "oidc_session_jwt_audience", None) or "").strip()
    return raw or DEFAULT_OIDC_SESSION_JWT_AUDIENCE


def resolve_breakglass_jwt_audience(settings: Settings) -> str:
    raw = (getattr(settings, "breakglass_jwt_audience", None) or "").strip()
    return raw or DEFAULT_BREAKGLASS_JWT_AUDIENCE
