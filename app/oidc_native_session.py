"""Per-realm gate for native OIDC bastion_session (pilot rollout)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import RealmConfig
from app.sso_settings import Settings


def parse_oidc_native_session_enabled_realms(settings: Settings) -> set[str]:
    """Env CSV allowlist (ops bootstrap) — slugs lowercased."""
    raw = (getattr(settings, "oidc_native_session_enabled_realms", None) or "").strip()
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
    1. ``RealmConfig.oidc_native_session_enabled`` (Admin UI toggle — preferred)
    2. Slug listed in ``OIDC_NATIVE_SESSION_ENABLED_REALMS`` (CSV env — no redeploy of UI)
    """
    slug = (realm_slug or "").strip()
    if not slug:
        return False
    if slug.lower() in parse_oidc_native_session_enabled_realms(settings):
        return True
    realm = (
        db.query(RealmConfig)
        .filter(RealmConfig.slug == slug)
        .first()
    )
    if realm is None:
        # Case-insensitive fallback for env/UI typos
        realm = (
            db.query(RealmConfig)
            .filter(RealmConfig.slug.ilike(slug))
            .first()
        )
    return bool(realm and getattr(realm, "oidc_native_session_enabled", False))


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
    current = bool(getattr(realm, "oidc_native_session_enabled", False))
    wanted = bool(enabled)
    if current == wanted:
        return False
    realm.oidc_native_session_enabled = wanted
    db.flush()
    return True


def _realm_by_slug(db: Session, realm_slug: str | None) -> RealmConfig | None:
    slug = (realm_slug or "").strip()
    if not slug:
        return None
    realm = db.query(RealmConfig).filter(RealmConfig.slug == slug).first()
    if realm is None:
        realm = (
            db.query(RealmConfig)
            .filter(RealmConfig.slug.ilike(slug))
            .first()
        )
    return realm


def is_oidc_mfa_enabled_for_realm(
    db: Session,
    realm_slug: str | None,
    *,
    realm: RealmConfig | None = None,
) -> bool:
    """
    Bastion MFA gate for native OIDC (enrollment + admin require-otp).

    Default True when the column is missing / realm unknown — fail open for
    already-enrolled OTP challenges; callers that need a hard deny should
    resolve the realm first.
    """
    row = realm if realm is not None else _realm_by_slug(db, realm_slug)
    if row is None:
        return True
    return bool(getattr(row, "oidc_mfa_enabled", True))


def set_oidc_mfa_enabled(
    db: Session,
    realm: RealmConfig,
    *,
    enabled: bool,
) -> bool:
    """Set MFA gate. Returns True if the value changed. Caller commits + audits."""
    current = bool(getattr(realm, "oidc_mfa_enabled", True))
    wanted = bool(enabled)
    if current == wanted:
        return False
    realm.oidc_mfa_enabled = wanted
    db.flush()
    return True
