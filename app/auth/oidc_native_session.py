"""Per-realm gate for native OIDC bastion_session (pilot rollout)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import RealmConfig
from app.realm_lookup import find_realm
from app.sso_settings import Settings


def parse_oidc_native_session_enabled_realms(settings: Settings) -> set[str]:
    """Env CSV allowlist (ops bootstrap) — slugs lowercased."""
    raw = (settings.oidc_native_session_enabled_realms or "").strip()
    if not raw:
        return set()
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def is_oidc_native_session_enabled_for_realm(
    db: Session,
    realm_slug: str | None,
    settings: Settings,
) -> bool:
    """
    True if this realm may accept / issue native ``bastion_session``.

    Sources (OR):
    1. Slug listed in ``OIDC_NATIVE_SESSION_ENABLED_REALMS`` (CSV env — no redeploy of UI)
    2. ``RealmConfig.oidc_native_session_enabled`` (Admin UI toggle — preferred)
    """
    slug = (realm_slug or "").strip()
    if not slug:
        return False
    if slug.lower() in parse_oidc_native_session_enabled_realms(settings):
        return True
    realm = find_realm(db, slug)
    return realm is not None and bool(realm.oidc_native_session_enabled)


def set_oidc_native_session_enabled(
    db: Session,
    realm: RealmConfig,
    *,
    enabled: bool,
) -> bool:
    """
    Set the DB toggle. Returns True if the value changed.
    Caller must commit + audit.
    """
    wanted = bool(enabled)
    if bool(realm.oidc_native_session_enabled) == wanted:
        return False
    realm.oidc_native_session_enabled = wanted
    db.flush()
    return True


def is_oidc_mfa_enabled_for_realm(
    db: Session,
    realm_slug: str | None,
    *,
    realm: RealmConfig | None = None,
) -> bool:
    """Bastion MFA gate for native OIDC (enrollment + admin require-otp).

    An unknown realm has no MFA policy to honour, so it is reported disabled.
    """
    row = realm if realm is not None else find_realm(db, realm_slug)
    return row is not None and bool(row.oidc_mfa_enabled)


def set_oidc_mfa_enabled(
    db: Session,
    realm: RealmConfig,
    *,
    enabled: bool,
) -> bool:
    """Set MFA gate. Returns True if the value changed. Caller commits + audits."""
    wanted = bool(enabled)
    if bool(realm.oidc_mfa_enabled) == wanted:
        return False
    realm.oidc_mfa_enabled = wanted
    db.flush()
    return True
