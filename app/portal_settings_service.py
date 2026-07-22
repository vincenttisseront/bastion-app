"""Portal-wide settings stored in DB (singleton row id=1)."""

from __future__ import annotations

import os
from typing import Mapping

from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import PortalSettings, utcnow
from app.sso_settings import Settings

PORTAL_SETTINGS_ID = 1


def parse_subdomain_sso_env(environ: Mapping[str, str] | None = None) -> bool:
    """Parse SUBDOMAIN_SSO_ENABLED from env (migration seed + Settings parity)."""
    env = environ if environ is not None else os.environ
    raw = env.get("SUBDOMAIN_SSO_ENABLED")
    if raw is None:
        raw = env.get("subdomain_sso_enabled")
    if raw is None:
        return False
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def get_portal_settings_row(db: Session) -> PortalSettings | None:
    return db.query(PortalSettings).filter_by(id=PORTAL_SETTINGS_ID).first()


def ensure_portal_settings(db: Session, settings: Settings) -> PortalSettings:
    """Return singleton row, creating it from env/Settings fallback if missing."""
    row = get_portal_settings_row(db)
    if row is not None:
        if getattr(row, "vault_key_rotation_days", None) is None:
            row.vault_key_rotation_days = int(settings.vault_key_rotation_days_default)
            db.commit()
            db.refresh(row)
        return row
    row = PortalSettings(
        id=PORTAL_SETTINGS_ID,
        subdomain_sso_enabled=bool(settings.subdomain_sso_enabled),
        vault_key_rotation_days=int(settings.vault_key_rotation_days_default),
        updated_at=utcnow(),
        updated_by=None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def get_vault_key_rotation_days(db: Session, settings: Settings) -> int:
    row = get_portal_settings_row(db)
    if row is None or not getattr(row, "vault_key_rotation_days", None):
        return max(1, int(settings.vault_key_rotation_days_default))
    return max(1, int(row.vault_key_rotation_days))


def set_vault_key_rotation_days(
    db: Session,
    settings: Settings,
    days: int,
    *,
    actor: str,
    ip_address: str | None = None,
) -> PortalSettings:
    row = ensure_portal_settings(db, settings)
    previous = int(row.vault_key_rotation_days)
    new_value = max(1, int(days))
    if previous == new_value:
        return row
    row.vault_key_rotation_days = new_value
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="portal_settings.vault_key_rotation_days",
        target="portal_settings",
        details={"previous": previous, "new": new_value},
        ip_address=ip_address,
    )
    return row


def get_subdomain_sso_enabled(db: Session, settings: Settings) -> bool:
    """
    DB value when portal_settings row exists; otherwise Settings/env fallback.
    """
    row = get_portal_settings_row(db)
    if row is None:
        return bool(settings.subdomain_sso_enabled)
    return bool(row.subdomain_sso_enabled)


def set_subdomain_sso_enabled(
    db: Session,
    settings: Settings,
    enabled: bool,
    *,
    actor: str,
    ip_address: str | None = None,
) -> PortalSettings:
    """Update subdomain SSO flag and audit the change."""
    row = ensure_portal_settings(db, settings)
    previous = bool(row.subdomain_sso_enabled)
    new_value = bool(enabled)
    if previous == new_value:
        return row
    row.subdomain_sso_enabled = new_value
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="portal_settings.subdomain_sso_enabled",
        target="portal_settings",
        details={
            "previous": previous,
            "new": new_value,
        },
        ip_address=ip_address,
    )
    return row


__all__ = [
    "PORTAL_SETTINGS_ID",
    "parse_subdomain_sso_env",
    "get_portal_settings_row",
    "ensure_portal_settings",
    "get_subdomain_sso_enabled",
    "set_subdomain_sso_enabled",
    "get_vault_key_rotation_days",
    "set_vault_key_rotation_days",
]
