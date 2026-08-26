"""Group-scoped vault credentials — shared Crush/robotic login per RBAC group."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy.orm import Session, joinedload

from app.audit import log_action
from app.models import (
    GroupAppCredential,
    GroupAppCredentialExclusion,
    RBACGroup,
    utcnow,
)
from app.secret_crypto import (
    encrypt_secret,
    encryption_config_error,
    encryption_configured,
)
from app.sso_settings import Settings
from app.vault.app_credential_service import EncryptionNotConfiguredError, VaultError


class GroupCredentialConflictError(VaultError):
    """Raised when a group already has a credential for the app."""


def _require_encryption(settings: Settings) -> None:
    if not encryption_configured(settings):
        raise EncryptionNotConfiguredError(encryption_config_error())


def list_group_credentials(
    db: Session,
    rbac_group_id: int,
) -> list[GroupAppCredential]:
    return (
        db.query(GroupAppCredential)
        .options(joinedload(GroupAppCredential.exclusions))
        .filter_by(rbac_group_id=rbac_group_id)
        .order_by(GroupAppCredential.app_slug)
        .all()
    )


def get_group_credential(
    db: Session,
    credential_id: int,
) -> GroupAppCredential | None:
    return (
        db.query(GroupAppCredential)
        .options(joinedload(GroupAppCredential.exclusions))
        .filter_by(id=credential_id)
        .first()
    )


def set_group_credential(
    db: Session,
    *,
    rbac_group_id: int,
    app_slug: str,
    robotic_username: str,
    plain_password: str | None,
    settings: Settings,
    priority: int = 100,
    actor: str = "system",
    ip_address: str | None = None,
) -> GroupAppCredential:
    """Create or update the group shared credential for one app.

    On update, an empty ``plain_password`` keeps the existing ciphertext.
    """
    _require_encryption(settings)
    slug = (app_slug or "").strip()
    username = (robotic_username or "").strip()
    password = (plain_password or "").strip()
    if not slug:
        raise VaultError("Application requise")
    if not username:
        raise VaultError("Nom d'utilisateur robotic requis")

    now = utcnow()
    cred = (
        db.query(GroupAppCredential)
        .filter_by(rbac_group_id=rbac_group_id, app_slug=slug)
        .first()
    )
    if cred is None:
        if not password:
            raise VaultError("Mot de passe requis")
        ciphertext = encrypt_secret(password, settings)
        cred = GroupAppCredential(
            rbac_group_id=rbac_group_id,
            app_slug=slug,
            robotic_username=username,
            encrypted_password=ciphertext,
            priority=int(priority),
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        db.add(cred)
    else:
        cred.robotic_username = username
        cred.priority = int(priority)
        cred.is_active = True
        cred.updated_at = now
        if password:
            cred.encrypted_password = encrypt_secret(password, settings)
            cred.rotated_at = now
    db.commit()
    db.refresh(cred)
    log_action(
        db,
        actor=actor,
        action="credential.group.set",
        target=f"group:{rbac_group_id}/app:{slug}",
        details={
            "rbac_group_id": rbac_group_id,
            "app_slug": slug,
            "robotic_username": username,
            "priority": int(priority),
            "password_rotated": bool(password),
        },
        ip_address=ip_address,
    )
    return cred


def delete_group_credential(
    db: Session,
    credential_id: int,
    *,
    actor: str = "system",
    ip_address: str | None = None,
) -> bool:
    cred = get_group_credential(db, credential_id)
    if cred is None:
        return False
    details = {
        "rbac_group_id": cred.rbac_group_id,
        "app_slug": cred.app_slug,
        "credential_id": cred.id,
    }
    db.delete(cred)
    db.commit()
    log_action(
        db,
        actor=actor,
        action="credential.group.delete",
        target=f"group:{details['rbac_group_id']}/app:{details['app_slug']}",
        details=details,
        ip_address=ip_address,
    )
    return True


def add_group_credential_exclusion(
    db: Session,
    credential_id: int,
    keycloak_user_id: str,
    *,
    actor: str = "system",
    ip_address: str | None = None,
) -> GroupAppCredentialExclusion:
    cred = get_group_credential(db, credential_id)
    if cred is None:
        raise VaultError("Compte groupe introuvable")
    uid = (keycloak_user_id or "").strip()
    if not uid:
        raise VaultError("Utilisateur Keycloak requis")
    existing = (
        db.query(GroupAppCredentialExclusion)
        .filter_by(group_app_credential_id=cred.id, keycloak_user_id=uid)
        .first()
    )
    if existing is not None:
        return existing
    row = GroupAppCredentialExclusion(
        group_app_credential_id=cred.id,
        keycloak_user_id=uid,
        created_at=utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="credential.group.exclusion_add",
        target=f"group:{cred.rbac_group_id}/app:{cred.app_slug}",
        details={
            "credential_id": cred.id,
            "keycloak_user_id": uid,
            "app_slug": cred.app_slug,
        },
        ip_address=ip_address,
    )
    return row


def remove_group_credential_exclusion(
    db: Session,
    credential_id: int,
    keycloak_user_id: str,
    *,
    actor: str = "system",
    ip_address: str | None = None,
) -> bool:
    uid = (keycloak_user_id or "").strip()
    row = (
        db.query(GroupAppCredentialExclusion)
        .filter_by(group_app_credential_id=credential_id, keycloak_user_id=uid)
        .first()
    )
    if row is None:
        return False
    cred = get_group_credential(db, credential_id)
    db.delete(row)
    db.commit()
    log_action(
        db,
        actor=actor,
        action="credential.group.exclusion_remove",
        target=(
            f"group:{cred.rbac_group_id}/app:{cred.app_slug}"
            if cred
            else f"credential:{credential_id}"
        ),
        details={
            "credential_id": credential_id,
            "keycloak_user_id": uid,
            "app_slug": cred.app_slug if cred else None,
        },
        ip_address=ip_address,
    )
    return True


def resolve_group_credential_for_user(
    db: Session,
    *,
    app_slug: str,
    keycloak_user_id: str | None,
    group_names: Sequence[str] | None,
) -> tuple[GroupAppCredential | None, bool]:
    """Pick the group shared credential for this user/app.

    Returns ``(credential, excluded_without_fallback)``.

    - ``(cred, False)`` — use this group credential
    - ``(None, True)`` — user is a member of a group that has a credential for
      this app but is excluded from every applicable one → block (no app shared)
    - ``(None, False)`` — no group credential applies → fall through to app shared
    """
    names = [n for n in (group_names or []) if n]
    if not names or not keycloak_user_id:
        return None, False

    groups = db.query(RBACGroup).filter(RBACGroup.name.in_(names)).all()
    if not groups:
        return None, False
    group_ids = [g.id for g in groups]

    candidates = (
        db.query(GroupAppCredential)
        .options(joinedload(GroupAppCredential.exclusions))
        .filter(
            GroupAppCredential.app_slug == app_slug,
            GroupAppCredential.rbac_group_id.in_(group_ids),
            GroupAppCredential.is_active.is_(True),
        )
        .all()
    )
    if not candidates:
        return None, False

    uid = keycloak_user_id.strip()
    usable: list[GroupAppCredential] = []
    for cred in candidates:
        excluded_ids = {e.keycloak_user_id for e in (cred.exclusions or [])}
        if uid in excluded_ids:
            continue
        usable.append(cred)

    if usable:
        usable.sort(key=lambda c: (-int(c.priority or 0), int(c.id or 0)))
        return usable[0], False

    # At least one group credential exists for this user's groups, but the user
    # is excluded from all of them → do not fall back to app-wide shared.
    return None, True


__all__ = [
    "GroupCredentialConflictError",
    "list_group_credentials",
    "get_group_credential",
    "set_group_credential",
    "delete_group_credential",
    "add_group_credential_exclusion",
    "remove_group_credential_exclusion",
    "resolve_group_credential_for_user",
]
