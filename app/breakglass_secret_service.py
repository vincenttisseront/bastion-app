"""UI-managed break-glass JWT HMAC secret (safety net when env var unset)."""

from __future__ import annotations

import hmac
import logging
from dataclasses import asdict, dataclass
from typing import Any, Literal

from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import utcnow
from app.portal_settings_service import ensure_portal_settings
from app.secret_crypto import decrypt_secret, encrypt_secret, generate_cookie_secret
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

SigningSource = Literal["env", "ui", "legacy", "ephemeral"]

AUDIT_GENERATED = "breakglass_secret_generated_from_ui"
AUDIT_ROTATED = "breakglass_secret_rotated_from_ui"


def secrets_equal(a: str, b: str) -> bool:
    """Constant-time equality; different lengths are never equal."""
    a_b = (a or "").encode("utf-8")
    b_b = (b or "").encode("utf-8")
    if len(a_b) != len(b_b):
        return False
    return hmac.compare_digest(a_b, b_b)


def secrets_are_distinct(a: str, b: str) -> bool:
    if not a:
        return False
    if not b:
        return True
    return not secrets_equal(a, b)


def get_ui_breakglass_secret(db: Session | None, settings: Settings) -> str | None:
    if db is None:
        return None
    row = ensure_portal_settings(db, settings)
    raw = (row.breakglass_jwt_secret_encrypted or "").strip()
    if not raw:
        return None
    try:
        plain = decrypt_secret(raw, settings).strip()
    except ValueError:
        logger.warning("failed to decrypt UI breakglass JWT secret")
        return None
    return plain or None


def get_ui_breakglass_previous_secret(
    db: Session | None, settings: Settings
) -> str | None:
    if db is None:
        return None
    row = ensure_portal_settings(db, settings)
    raw = (row.breakglass_jwt_secret_previous_encrypted or "").strip()
    if not raw:
        return None
    try:
        plain = decrypt_secret(raw, settings).strip()
    except ValueError:
        logger.warning("failed to decrypt previous UI breakglass JWT secret")
        return None
    return plain or None


def env_breakglass_secret_defined(settings: Settings) -> bool:
    return bool((settings.breakglass_jwt_secret or "").strip())


@dataclass(frozen=True)
class BreakglassSecretStatus:
    """Booleans only — never includes secret material."""

    env_defined: bool
    ui_secret_present: bool
    ui_secret_active: bool
    effective_source: SigningSource
    effective_distinct_from_vault_token: bool
    legacy_fallback_enabled: bool
    conforming: bool
    can_generate: bool
    can_rotate: bool

    def to_public_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_breakglass_secret_status(
    settings: Settings,
    db: Session | None,
    *,
    effective_secret: str,
    effective_source: SigningSource,
) -> BreakglassSecretStatus:
    env_defined = env_breakglass_secret_defined(settings)
    ui_present = get_ui_breakglass_secret(db, settings) is not None
    ui_active = (not env_defined) and effective_source == "ui"
    vault = (settings.vault_portal_internal_token or "").strip()
    distinct = secrets_are_distinct(effective_secret, vault)
    dedicated_active = effective_source in ("env", "ui")
    conforming = dedicated_active and distinct
    return BreakglassSecretStatus(
        env_defined=env_defined,
        ui_secret_present=ui_present,
        ui_secret_active=ui_active,
        effective_source=effective_source,
        effective_distinct_from_vault_token=distinct,
        legacy_fallback_enabled=bool(settings.breakglass_jwt_secret_fallback_enabled),
        conforming=conforming,
        can_generate=(not env_defined) and (not ui_present),
        can_rotate=(not env_defined) and ui_present,
    )


def generate_or_rotate_ui_breakglass_secret(
    db: Session,
    settings: Settings,
    *,
    actor: str,
    ip_address: str | None = None,
) -> BreakglassSecretStatus:
    """
    Generate (or rotate) the UI-stored break-glass HMAC secret.

    Refuses if ``BREAKGLASS_JWT_SECRET`` env is already set (AWX owns that channel).
    Never returns or logs plaintext.
    """
    if env_breakglass_secret_defined(settings):
        raise PermissionError(
            "BREAKGLASS_JWT_SECRET is set via environment; UI must not override AWX"
        )

    row = ensure_portal_settings(db, settings)
    previous_cipher = (row.breakglass_jwt_secret_encrypted or "").strip() or None
    is_rotation = bool(previous_cipher)

    new_plain = generate_cookie_secret()
    row.breakglass_jwt_secret_encrypted = encrypt_secret(new_plain, settings)
    if previous_cipher:
        row.breakglass_jwt_secret_previous_encrypted = previous_cipher
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)

    log_action(
        db,
        actor=actor,
        action=AUDIT_ROTATED if is_rotation else AUDIT_GENERATED,
        target="portal_settings",
        details={"rotated": is_rotation},
        ip_address=ip_address,
    )

    from app.breakglass import resolve_breakglass_signing_secret_with_source

    secret, source = resolve_breakglass_signing_secret_with_source(settings, db=db)
    return build_breakglass_secret_status(
        settings, db, effective_secret=secret, effective_source=source
    )
