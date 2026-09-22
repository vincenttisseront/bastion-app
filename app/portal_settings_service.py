"""Portal-wide settings stored in DB (singleton row id=1)."""

from __future__ import annotations

import os
from typing import Any, Mapping

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


def _smtp_optional_str(value: str | None) -> str | None:
    return (value or "").strip() or None


def _clamp_recap_hour(raw: int | None) -> int:
    try:
        hour = int(raw) if raw is not None else 7
    except (TypeError, ValueError):
        hour = 7
    return max(0, min(23, hour))


def _require_smtp_fields(fields: dict[str, Any]) -> None:
    if fields["enabled"] and not fields["host"]:
        raise ValueError("Hôte SMTP requis lorsque SMTP est activé")
    if fields["enabled"] and not fields["from_email"]:
        raise ValueError("Expéditeur requis lorsque SMTP est activé")
    if fields["recap_on"] and not (fields["recap_email"] or fields["from_email"]):
        raise ValueError(
            "Destinataire du récap (ou expéditeur SMTP) requis lorsque le récap est activé"
        )
    if fields["recap_email"] and "@" not in fields["recap_email"]:
        raise ValueError("Adresse du récap quotidien invalide")


def _normalize_smtp_fields(raw: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "enabled": bool(raw.get("smtp_enabled")),
        "host": _smtp_optional_str(raw.get("smtp_host")),
        "port": int(raw["smtp_port"]) if raw.get("smtp_port") else 587,
        "use_tls": bool(raw.get("smtp_use_tls")),
        "username": _smtp_optional_str(raw.get("smtp_username")),
        "from_email": _smtp_optional_str(raw.get("smtp_from_email")),
        "from_name": _smtp_optional_str(raw.get("smtp_from_name")),
        "recap_on": bool(raw.get("daily_recap_enabled")),
        "recap_email": _smtp_optional_str(raw.get("daily_recap_email")),
        "recap_hour": _clamp_recap_hour(raw.get("daily_recap_hour")),
    }
    _require_smtp_fields(fields)
    return fields


def update_smtp_settings(
    db: Session,
    settings: Settings,
    *,
    actor: str,
    ip_address: str | None = None,
    smtp_enabled: bool,
    smtp_host: str | None,
    smtp_port: int | None,
    smtp_use_tls: bool,
    smtp_username: str | None,
    smtp_password: str | None,
    smtp_from_email: str | None,
    smtp_from_name: str | None,
    daily_recap_enabled: bool = False,
    daily_recap_email: str | None = None,
    daily_recap_hour: int | None = 7,
) -> PortalSettings:
    """Persist global SMTP settings. Empty password keeps the existing secret."""
    from app.secret_crypto import encrypt_secret

    row = ensure_portal_settings(db, settings)
    fields = _normalize_smtp_fields(
        {
            "smtp_enabled": smtp_enabled,
            "smtp_host": smtp_host,
            "smtp_port": smtp_port,
            "smtp_use_tls": smtp_use_tls,
            "smtp_username": smtp_username,
            "smtp_from_email": smtp_from_email,
            "smtp_from_name": smtp_from_name,
            "daily_recap_enabled": daily_recap_enabled,
            "daily_recap_email": daily_recap_email,
            "daily_recap_hour": daily_recap_hour,
        }
    )

    previous_enabled = bool(row.smtp_enabled)
    row.smtp_enabled = fields["enabled"]
    row.smtp_host = fields["host"]
    row.smtp_port = fields["port"]
    row.smtp_use_tls = fields["use_tls"]
    row.smtp_username = fields["username"]
    row.smtp_from_email = fields["from_email"]
    row.smtp_from_name = fields["from_name"]
    row.daily_recap_enabled = fields["recap_on"]
    row.daily_recap_email = fields["recap_email"]
    row.daily_recap_hour = fields["recap_hour"]

    pwd = (smtp_password or "").strip()
    password_updated = False
    if pwd:
        row.smtp_password_encrypted = encrypt_secret(pwd, settings)
        password_updated = True

    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="portal_settings.smtp_updated",
        target="portal_settings",
        details={
            "smtp_enabled": fields["enabled"],
            "previous_enabled": previous_enabled,
            "smtp_host": fields["host"],
            "smtp_port": fields["port"],
            "smtp_use_tls": fields["use_tls"],
            "smtp_from_email": fields["from_email"],
            "password_updated": password_updated,
            "daily_recap_enabled": fields["recap_on"],
            "daily_recap_hour": fields["recap_hour"],
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
    "update_smtp_settings",
]
