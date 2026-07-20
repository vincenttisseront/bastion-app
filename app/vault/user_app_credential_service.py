"""User-scoped vault overrides — resolve shared vs per-user credentials."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import AppCredential, UserAppCredential, utcnow
from app.secret_crypto import (
    decrypt_secret,
    encrypt_secret,
    encryption_config_error,
    encryption_configured,
)
from app.sso_settings import Settings
from app.vault.app_credential_service import (
    CredentialDecryptError,
    CredentialNotFoundError,
    EncryptionNotConfiguredError,
    VaultError,
    get_app_credential,
)

logger = logging.getLogger(__name__)

CredentialSource = Literal["shared", "user_override"]


@dataclass(frozen=True)
class ResolvedCredential:
    """Driver-facing credential — decoupled from SQLAlchemy models."""

    robotic_username: str
    app_slug: str
    source: CredentialSource


def _require_encryption(settings: Settings) -> None:
    if not encryption_configured(settings):
        raise EncryptionNotConfiguredError(encryption_config_error())


def get_user_credential(
    db: Session,
    app_slug: str,
    keycloak_user_id: str,
) -> UserAppCredential | None:
    return (
        db.query(UserAppCredential)
        .filter_by(app_slug=app_slug, keycloak_user_id=keycloak_user_id)
        .first()
    )


def has_user_override(
    db: Session,
    app_slug: str,
    keycloak_user_id: str,
) -> bool:
    cred = get_user_credential(db, app_slug, keycloak_user_id)
    return cred is not None and bool(cred.is_active)


def get_effective_credential(
    db: Session,
    app_slug: str,
    keycloak_user_id: str | None,
) -> tuple[AppCredential | UserAppCredential | None, CredentialSource | None]:
    """
    Resolve vault credential: user override first, then shared AppCredential.

    When app.credential_mode == "individual_required", never fall back to shared.
    Returns (credential_row_or_None, source_or_None).
    """
    from app.bastion.bastion_fields import normalize_credential_mode
    from app.models import App

    app = db.query(App).filter_by(slug=app_slug).first()
    mode = normalize_credential_mode(app.credential_mode if app else None)

    if keycloak_user_id:
        user_cred = get_user_credential(db, app_slug, keycloak_user_id)
        if user_cred is not None and user_cred.is_active:
            return user_cred, "user_override"

    if mode == "individual_required":
        return None, None

    shared = get_app_credential(db, app_slug)
    if shared is not None and shared.is_active:
        return shared, "shared"
    return None, None


def needs_individual_credential_setup(
    db: Session,
    app: object,
    keycloak_user_id: str | None,
) -> bool:
    """True when app requires a per-user override and the user has none."""
    from app.bastion.bastion_fields import normalize_credential_mode, vault_enabled_for_app

    if not keycloak_user_id:
        return False
    if not vault_enabled_for_app(
        getattr(app, "auth_mode", None),
        getattr(app, "robotic_driver", None),
    ):
        return False
    if normalize_credential_mode(getattr(app, "credential_mode", None)) != "individual_required":
        return False
    return not has_user_override(db, app.slug, keycloak_user_id)


def resolve_credential(
    db: Session,
    app_slug: str,
    settings: Settings,
    keycloak_user_id: str | None = None,
) -> tuple[ResolvedCredential, str]:
    """
    Return (ResolvedCredential, plaintext_password).

    Never log or return the password outside this call site's short-lived use.
    """
    _require_encryption(settings)
    row, source = get_effective_credential(db, app_slug, keycloak_user_id)
    if row is None or source is None:
        raise CredentialNotFoundError(f"No active credential for app '{app_slug}'")
    try:
        password = decrypt_secret(row.encrypted_password, settings)
    except ValueError as exc:
        raise CredentialDecryptError(
            f"Failed to decrypt credential for app '{app_slug}'"
        ) from exc
    return (
        ResolvedCredential(
            robotic_username=row.robotic_username,
            app_slug=app_slug,
            source=source,
        ),
        password,
    )


def set_user_credential(
    db: Session,
    app_slug: str,
    keycloak_user_id: str,
    robotic_username: str,
    plain_password: str,
    settings: Settings,
    *,
    actor: str = "system",
    ip_address: str | None = None,
) -> UserAppCredential:
    _require_encryption(settings)
    ciphertext = encrypt_secret(plain_password, settings)
    cred = get_user_credential(db, app_slug, keycloak_user_id)
    now = utcnow()
    if cred is None:
        cred = UserAppCredential(
            app_slug=app_slug,
            keycloak_user_id=keycloak_user_id,
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
        cred.rotated_at = now
    db.commit()
    db.refresh(cred)
    log_action(
        db,
        actor=actor,
        action="credential.user.set",
        target=f"app:{app_slug}/user:{keycloak_user_id}",
        details={
            "app_slug": app_slug,
            "keycloak_user_id": keycloak_user_id,
            "robotic_username": robotic_username,
        },
        ip_address=ip_address,
    )
    return cred


def delete_user_credential(
    db: Session,
    app_slug: str,
    keycloak_user_id: str,
    *,
    actor: str = "system",
    ip_address: str | None = None,
) -> bool:
    """Remove user override (return to shared credential). Returns True if deleted."""
    cred = get_user_credential(db, app_slug, keycloak_user_id)
    if cred is None:
        return False
    db.delete(cred)
    db.commit()
    log_action(
        db,
        actor=actor,
        action="credential.user.delete",
        target=f"app:{app_slug}/user:{keycloak_user_id}",
        details={"app_slug": app_slug, "keycloak_user_id": keycloak_user_id},
        ip_address=ip_address,
    )
    return True


__all__ = [
    "CredentialSource",
    "ResolvedCredential",
    "VaultError",
    "EncryptionNotConfiguredError",
    "CredentialNotFoundError",
    "CredentialDecryptError",
    "get_user_credential",
    "has_user_override",
    "get_effective_credential",
    "needs_individual_credential_setup",
    "resolve_credential",
    "set_user_credential",
    "delete_user_credential",
]
