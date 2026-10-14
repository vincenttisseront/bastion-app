"""Fernet key rotation for the application vault (portal.db ciphertext columns).

One logical key protects every ``*_encrypted`` column listed in ``_ENCRYPTED_COLUMNS``.
Key material lives in VAULT_KEYS_DIR; rotate_application_key() drives in-process
rotation. rotate_fernet_key() remains the transactional re-encrypt core.
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
from app.models import (
    AcmeSettings,
    App,
    AppCredential,
    GroupAppCredential,
    OidcLoginAttempt,
    PortalSettings,
    RealmConfig,
    SiemForwardingSettings,
    UserAppCredential,
    utcnow,
)
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
    group_app_credentials: int = 0
    app_crushftp_admin_passwords: int = 0
    realm_client_secrets: int = 0
    realm_oauth2_cookie_secrets: int = 0
    realm_admin_client_secrets: int = 0
    realm_provision_client_secrets: int = 0
    realm_oidc_bff_client_secrets: int = 0
    portal_breakglass_jwt_secrets: int = 0
    portal_session_hop_secrets: int = 0
    portal_oidc_session_jwt_secrets: int = 0
    portal_smtp_passwords: int = 0
    portal_hot_store_passwords: int = 0
    siem_webhook_secrets: int = 0
    acme_cf_tokens: int = 0
    oidc_login_attempts: int = 0
    duration_ms: float = 0.0
    error: str | None = None

    @property
    def total(self) -> int:
        return sum(getattr(self, counter) for counter in _COUNTERS)

    def to_audit_details(self) -> dict[str, Any]:
        data = asdict(self)
        data["total"] = self.total
        return data


# Every Fernet column of portal.db: (model, ((column, report counter), ...)).
# A column missing here stays encrypted with the retired key after rotation.
_ENCRYPTED_COLUMNS: tuple[tuple[type, tuple[tuple[str, str], ...]], ...] = (
    (AppCredential, (("encrypted_password", "app_credentials"),)),
    (UserAppCredential, (("encrypted_password", "user_app_credentials"),)),
    (GroupAppCredential, (("encrypted_password", "group_app_credentials"),)),
    (App, (("crushftp_admin_password_encrypted", "app_crushftp_admin_passwords"),)),
    (
        RealmConfig,
        (
            ("client_secret_encrypted", "realm_client_secrets"),
            ("oauth2_cookie_secret_encrypted", "realm_oauth2_cookie_secrets"),
            ("keycloak_admin_client_secret_encrypted", "realm_admin_client_secrets"),
            ("keycloak_provision_client_secret_encrypted", "realm_provision_client_secrets"),
            ("oidc_bff_client_secret_encrypted", "realm_oidc_bff_client_secrets"),
        ),
    ),
    (
        PortalSettings,
        (
            ("breakglass_jwt_secret_encrypted", "portal_breakglass_jwt_secrets"),
            ("breakglass_jwt_secret_previous_encrypted", "portal_breakglass_jwt_secrets"),
            ("session_hop_secret_encrypted", "portal_session_hop_secrets"),
            ("oidc_session_jwt_secret_encrypted", "portal_oidc_session_jwt_secrets"),
            ("smtp_password_encrypted", "portal_smtp_passwords"),
            ("hot_store_password_encrypted", "portal_hot_store_passwords"),
        ),
    ),
    (SiemForwardingSettings, (("webhook_auth_secret_encrypted", "siem_webhook_secrets"),)),
    (AcmeSettings, (("cf_token_encrypted", "acme_cf_tokens"),)),
    (
        OidcLoginAttempt,
        (
            ("keycloak_cookies_encrypted", "oidc_login_attempts"),
            ("otp_form_encrypted", "oidc_login_attempts"),
        ),
    ),
)

_COUNTERS: tuple[str, ...] = tuple(
    dict.fromkeys(counter for _, cols in _ENCRYPTED_COLUMNS for _, counter in cols)
)


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
    counts = dict.fromkeys(_COUNTERS, 0)

    try:
        for model, columns in _ENCRYPTED_COLUMNS:
            for row in db.query(model).all():
                for column, counter in columns:
                    ciphertext = getattr(row, column)
                    if not ciphertext or not str(ciphertext).strip():
                        continue
                    setattr(row, column, _reencrypt_field(ciphertext, old_material, new_material))
                    counts[counter] += 1
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
        # Everything was rolled back: report zero rows re-encrypted.
        report = RotationReport(success=False, duration_ms=duration_ms, error=err)
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


def _backup_files_storage(settings: Settings) -> Path | None:
    """Tar FILES_STORAGE_DIR beside portal.db backups (avoid orphan storage_path)."""
    from app.files.service import get_files_storage_root

    root = get_files_storage_root(settings)
    if not root.is_dir():
        return None
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    dest = root.parent / f"files.bak-pre-rotation-{stamp}.tgz"
    import tarfile

    with tarfile.open(dest, "w:gz") as tar:
        tar.add(root, arcname=root.name)
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
    _backup_files_storage(settings)
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
