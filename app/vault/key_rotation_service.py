"""Fernet key rotation for the application vault (portal.db ciphertext columns).

One logical key protects AppCredential, UserAppCredential and RealmConfig secrets.
Phase B: key material lives in VAULT_KEYS_DIR; rotate_application_key() drives
in-process rotation. rotate_fernet_key() remains the transactional re-encrypt core.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import InvalidToken
from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import AppCredential, RealmConfig, UserAppCredential, utcnow
from app.secret_crypto import decrypt_with_key, encrypt_with_key
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

AUDIT_ACTION = "key_rotation"


class KeyRotationError(Exception):
    """Raised when re-encryption fails — DB must be rolled back to a single-key state."""


@dataclass(frozen=True)
class RotationReport:
    """Counters only — never includes plaintext secrets or key material."""

    success: bool
    app_credentials: int = 0
    user_app_credentials: int = 0
    realm_client_secrets: int = 0
    realm_oauth2_cookie_secrets: int = 0
    realm_admin_client_secrets: int = 0
    duration_ms: float = 0.0
    error: str | None = None

    @property
    def total(self) -> int:
        return (
            self.app_credentials
            + self.user_app_credentials
            + self.realm_client_secrets
            + self.realm_oauth2_cookie_secrets
            + self.realm_admin_client_secrets
        )

    def to_audit_details(self) -> dict[str, Any]:
        data = asdict(self)
        data["total"] = self.total
        return data


def _reencrypt_field(ciphertext: str | None, old_key: str, new_key: str) -> str | None:
    if ciphertext is None or not str(ciphertext).strip():
        return ciphertext
    try:
        plain = decrypt_with_key(ciphertext, old_key)
    except (ValueError, InvalidToken) as exc:
        raise KeyRotationError("decrypt failed for a ciphertext row") from exc
    return encrypt_with_key(plain, new_key)


def rotate_fernet_key(
    db: Session,
    old_key: str,
    new_key: str,
    *,
    actor: str = "system",
    ip_address: str | None = None,
    extra_details: dict[str, Any] | None = None,
) -> RotationReport:
    """
    Re-encrypt all Fernet columns with new_key in a single DB transaction.

    On any row failure the session is rolled back — no mixed old/new key state.
    Never logs plaintext or key material; logs per-table counts only.
    """
    old_material = (old_key or "").strip()
    new_material = (new_key or "").strip()
    if not old_material or not new_material:
        raise KeyRotationError("old_key and new_key are required (non-empty)")
    if old_material == new_material:
        raise KeyRotationError("old_key and new_key must differ")

    started = time.perf_counter()
    counts = {
        "app_credentials": 0,
        "user_app_credentials": 0,
        "realm_client_secrets": 0,
        "realm_oauth2_cookie_secrets": 0,
        "realm_admin_client_secrets": 0,
    }

    try:
        for cred in db.query(AppCredential).all():
            cred.encrypted_password = _reencrypt_field(
                cred.encrypted_password, old_material, new_material
            )
            counts["app_credentials"] += 1

        for cred in db.query(UserAppCredential).all():
            cred.encrypted_password = _reencrypt_field(
                cred.encrypted_password, old_material, new_material
            )
            counts["user_app_credentials"] += 1

        for realm in db.query(RealmConfig).all():
            if realm.client_secret_encrypted and str(realm.client_secret_encrypted).strip():
                realm.client_secret_encrypted = _reencrypt_field(
                    realm.client_secret_encrypted, old_material, new_material
                )
                counts["realm_client_secrets"] += 1
            if (
                realm.oauth2_cookie_secret_encrypted
                and str(realm.oauth2_cookie_secret_encrypted).strip()
            ):
                realm.oauth2_cookie_secret_encrypted = _reencrypt_field(
                    realm.oauth2_cookie_secret_encrypted, old_material, new_material
                )
                counts["realm_oauth2_cookie_secrets"] += 1
            if (
                realm.keycloak_admin_client_secret_encrypted
                and str(realm.keycloak_admin_client_secret_encrypted).strip()
            ):
                realm.keycloak_admin_client_secret_encrypted = _reencrypt_field(
                    realm.keycloak_admin_client_secret_encrypted,
                    old_material,
                    new_material,
                )
                counts["realm_admin_client_secrets"] += 1

        db.commit()
    except Exception as exc:
        db.rollback()
        duration_ms = (time.perf_counter() - started) * 1000
        logger.exception(
            "fernet key rotation failed after processing counts=%s duration_ms=%.1f",
            counts,
            duration_ms,
        )
        err = str(exc) if isinstance(exc, KeyRotationError) else "rotation failed"
        report = RotationReport(
            success=False,
            duration_ms=duration_ms,
            error=err,
            **counts,
        )
        details = report.to_audit_details()
        if extra_details:
            details.update(extra_details)
        log_action(
            db,
            actor=actor,
            action=AUDIT_ACTION,
            target="vault:fernet",
            details=details,
            ip_address=ip_address,
        )
        if isinstance(exc, KeyRotationError):
            raise
        raise KeyRotationError("rotation failed") from exc

    duration_ms = (time.perf_counter() - started) * 1000
    report = RotationReport(success=True, duration_ms=duration_ms, **counts)
    logger.info(
        "fernet key rotation ok tables=%s total=%s duration_ms=%.1f",
        counts,
        report.total,
        duration_ms,
    )
    details = report.to_audit_details()
    if extra_details:
        details.update(extra_details)
    log_action(
        db,
        actor=actor,
        action=AUDIT_ACTION,
        target="vault:fernet",
        details=details,
        ip_address=ip_address,
    )
    return report


def _backup_portal_db(settings: Settings) -> Path | None:
    from sqlalchemy.engine.url import make_url

    url = make_url(settings.database_url)
    if url.get_backend_name() != "sqlite" or not url.database:
        return None
    db_path = Path(url.database)
    if not db_path.is_file():
        return None
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    dest = db_path.with_name(f"{db_path.name}.bak-pre-rotation-{stamp}")
    shutil.copy2(db_path, dest)
    try:
        os.chmod(dest, 0o640)
    except OSError:
        pass
    return dest


def rotate_application_key(
    db: Session,
    settings: Settings,
    *,
    actor: str = "system",
    ip_address: str | None = None,
) -> RotationReport:
    """
    In-process rotation (§8.5): write fernet_v{N+1}, re-encrypt, activate on success,
    delete orphan file on failure. Never auto-called — admin click only.
    """
    from cryptography.fernet import Fernet

    from app.vault.encryption_key_store import (
        activate_new_key_version,
        backup_active_key_file,
        delete_key_file,
        get_active_key,
        get_active_version,
        next_key_version,
        register_pending_version,
        write_pending_key,
    )

    old_material = get_active_key()
    old_version = get_active_version()
    if old_version is None:
        raise KeyRotationError("no active key version")

    _backup_portal_db(settings)
    backup_active_key_file(settings)

    new_version = next_key_version(db, settings)
    new_material = Fernet.generate_key().decode("ascii")
    write_pending_key(settings, new_version, new_material)
    register_pending_version(db, new_version)

    try:
        report = rotate_fernet_key(
            db,
            old_material,
            new_material,
            actor=actor,
            ip_address=ip_address,
            extra_details={"from_version": old_version, "to_version": new_version},
        )
        activate_new_key_version(
            db,
            settings,
            new_version=new_version,
            new_material=new_material,
            old_version=old_version,
        )
        return report
    except Exception:
        delete_key_file(settings, new_version)
        raise
