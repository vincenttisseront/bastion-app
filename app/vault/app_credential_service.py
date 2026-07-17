"""Vault service for app-scoped robotic credentials (Fernet via secret_crypto)."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import AppCredential, utcnow
from app.secret_crypto import (
    decrypt_secret,
    encrypt_secret,
    encryption_config_error,
    encryption_configured,
)
from app.sso_settings import Settings

logger = logging.getLogger(__name__)


class VaultError(Exception):
    """Base vault error — messages must never include plaintext secrets."""


class EncryptionNotConfiguredError(VaultError):
    """Raised when Fernet encryption is not configured."""


class CredentialNotFoundError(VaultError):
    """Raised when no active credential exists for an app."""


class CredentialDecryptError(VaultError):
    """Raised when ciphertext cannot be decrypted."""


def _require_encryption(settings: Settings) -> None:
    if not encryption_configured(settings):
        raise EncryptionNotConfiguredError(encryption_config_error())


def get_app_credential(db: Session, app_slug: str) -> AppCredential | None:
    return db.query(AppCredential).filter_by(app_slug=app_slug).first()


def set_app_credential(
    db: Session,
    app_slug: str,
    robotic_username: str,
    plain_password: str,
    settings: Settings,
    *,
    actor: str = "system",
    ip_address: str | None = None,
) -> AppCredential:
    _require_encryption(settings)
    ciphertext = encrypt_secret(plain_password, settings)
    cred = get_app_credential(db, app_slug)
    now = utcnow()
    if cred is None:
        cred = AppCredential(
            app_slug=app_slug,
            robotic_username=robotic_username,
            encrypted_password=ciphertext,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        db.add(cred)
    else:
        cred.robotic_username = robotic_username
        cred.encrypted_password = ciphertext
        cred.is_active = True
        cred.updated_at = now
    db.commit()
    db.refresh(cred)
    log_action(
        db,
        actor=actor,
        action="credential.set",
        target=f"app:{app_slug}",
        details={"app_slug": app_slug, "robotic_username": robotic_username},
        ip_address=ip_address,
    )
    return cred


def get_decrypted_password(db: Session, app_slug: str, settings: Settings) -> str:
    _require_encryption(settings)
    cred = get_app_credential(db, app_slug)
    if cred is None or not cred.is_active:
        raise CredentialNotFoundError(f"No active credential for app '{app_slug}'")
    try:
        return decrypt_secret(cred.encrypted_password, settings)
    except ValueError as exc:
        raise CredentialDecryptError(
            f"Failed to decrypt credential for app '{app_slug}'"
        ) from exc


def rotate_app_credential(
    db: Session,
    app_slug: str,
    new_plain_password: str,
    settings: Settings,
    *,
    actor: str = "system",
    ip_address: str | None = None,
) -> AppCredential:
    _require_encryption(settings)
    cred = get_app_credential(db, app_slug)
    if cred is None:
        raise CredentialNotFoundError(f"No credential for app '{app_slug}'")
    now = utcnow()
    cred.encrypted_password = encrypt_secret(new_plain_password, settings)
    cred.rotated_at = now
    cred.updated_at = now
    cred.is_active = True
    db.commit()
    db.refresh(cred)
    log_action(
        db,
        actor=actor,
        action="credential.rotate",
        target=f"app:{app_slug}",
        details={"app_slug": app_slug},
        ip_address=ip_address,
    )
    return cred


def deactivate_app_credential(
    db: Session,
    app_slug: str,
    *,
    actor: str = "system",
    ip_address: str | None = None,
) -> None:
    cred = get_app_credential(db, app_slug)
    if cred is None:
        return
    cred.is_active = False
    cred.updated_at = utcnow()
    db.commit()
    log_action(
        db,
        actor=actor,
        action="credential.deactivate",
        target=f"app:{app_slug}",
        details={"app_slug": app_slug},
        ip_address=ip_address,
    )
