"""Application-managed Fernet key store (files on disk + DB metadata).

Key material never enters the database — only version metadata.
Resolution order at boot (ensure_encryption_key):
  1. Active file pointed by keys/current
  2. Migrate from PORTAL_SECRET_ENCRYPTION_KEY / VAULT_PORTAL_VAULT_FERNET_KEY
  3. Generate a new key (greenfield)
"""

from __future__ import annotations

import logging
import os
import shutil
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import EncryptionKeyVersion, utcnow
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

STATUS_ACTIVE = "active"
STATUS_RETIRED = "retired"
STATUS_PENDING = "pending"

CURRENT_POINTER = "current"
KEY_FILE_TMPL = "fernet_v{version}.key"
BACKUP_MAGIC = b"bastion-fernet-backup-v1\n"
PBKDF2_ITERATIONS = 390_000

_active_material: str | None = None
_active_version: int | None = None


class EncryptionKeyStoreError(RuntimeError):
    """Fatal key-store error — startup must fail-fast."""


@dataclass(frozen=True)
class VaultKeyStatus:
    version: int
    created_at: datetime | None
    activated_at: datetime | None
    age_days: int
    rotation_days: int
    rotation_recommended: bool
    next_due_at: datetime | None
    status_badge: str  # ok | recommended | rotating
    keys_dir: str
    source: str | None


def resolve_keys_dir(settings: Settings) -> Path:
    configured = (settings.vault_keys_dir or "").strip()
    if configured:
        return Path(configured)
    return Path(settings.portal_data_dir) / "keys"


def key_path(keys_dir: Path, version: int) -> Path:
    return keys_dir / KEY_FILE_TMPL.format(version=version)


def current_pointer_path(keys_dir: Path) -> Path:
    return keys_dir / CURRENT_POINTER


def try_get_active_key() -> str | None:
    return _active_material


def get_active_key() -> str:
    if not _active_material:
        raise EncryptionKeyStoreError(
            "encryption key not initialized — call ensure_encryption_key() at startup"
        )
    return _active_material


def get_active_version() -> int | None:
    return _active_version


def get_key_by_version(settings: Settings, version: int) -> str:
    path = key_path(resolve_keys_dir(settings), version)
    if not path.is_file():
        raise EncryptionKeyStoreError(f"key file for version {version} not found")
    return path.read_text(encoding="ascii").strip()


def _set_active_cache(material: str, version: int) -> None:
    global _active_material, _active_version
    _active_material = material.strip()
    _active_version = version


def reset_active_cache_for_tests() -> None:
    """Clear in-memory cache (unit tests only)."""
    global _active_material, _active_version
    _active_material = None
    _active_version = None


def _ensure_keys_dir(keys_dir: Path) -> None:
    try:
        keys_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise EncryptionKeyStoreError(
            f"vault keys directory not creatable: {keys_dir}"
        ) from exc
    try:
        os.chmod(keys_dir, stat.S_IRWXU)  # 0700
    except OSError as exc:
        raise EncryptionKeyStoreError(
            f"cannot set permissions on vault keys directory: {keys_dir}"
        ) from exc
    if not os.access(keys_dir, os.R_OK | os.W_OK | os.X_OK):
        raise EncryptionKeyStoreError(
            f"vault keys directory not writable: {keys_dir}"
        )


def _write_key_file(path: Path, material: str) -> None:
    path.write_text(material.strip() + "\n", encoding="ascii")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError as exc:
        raise EncryptionKeyStoreError(f"cannot set permissions on {path}") from exc


def _read_current_version(keys_dir: Path) -> int | None:
    pointer = current_pointer_path(keys_dir)
    if not pointer.is_file():
        return None
    raw = pointer.read_text(encoding="utf-8").strip()
    if not raw.isdigit():
        raise EncryptionKeyStoreError(f"invalid current version pointer: {pointer}")
    return int(raw)


def _write_current_version(keys_dir: Path, version: int) -> None:
    pointer = current_pointer_path(keys_dir)
    pointer.write_text(f"{version}\n", encoding="utf-8")
    try:
        os.chmod(pointer, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _env_key_material(settings: Settings) -> str:
    raw = (settings.portal_secret_encryption_key or "").strip()
    if not raw:
        raw = (settings.vault_portal_vault_fernet_key or "").strip()
    return raw


def _upsert_version_row(
    db: Session,
    *,
    version: int,
    status: str,
    source: str,
    activated: bool,
) -> EncryptionKeyVersion:
    row = db.query(EncryptionKeyVersion).filter_by(version=version).first()
    now = utcnow()
    if row is None:
        row = EncryptionKeyVersion(
            version=version,
            status=status,
            created_at=now,
            activated_at=now if activated else None,
            source=source,
        )
        db.add(row)
    else:
        row.status = status
        row.source = source or row.source
        if activated and row.activated_at is None:
            row.activated_at = now
    db.commit()
    db.refresh(row)
    return row


def ensure_encryption_key(db: Session, settings: Settings) -> int:
    """
    Load / migrate / generate the active Fernet key. Fail-fast on store errors.
    Returns the active version number.
    """
    keys_dir = resolve_keys_dir(settings)
    _ensure_keys_dir(keys_dir)

    version = _read_current_version(keys_dir)
    if version is not None:
        path = key_path(keys_dir, version)
        if not path.is_file():
            raise EncryptionKeyStoreError(
                f"current_version={version} but missing file {path.name}"
            )
        material = path.read_text(encoding="ascii").strip()
        if not material:
            raise EncryptionKeyStoreError(f"empty key file: {path}")
        _set_active_cache(material, version)
        _upsert_version_row(
            db, version=version, status=STATUS_ACTIVE, source="loaded", activated=True
        )
        logger.info("encryption key loaded from store version=%s", version)
        return version

    env_material = _env_key_material(settings)
    if env_material:
        version = 1
        _write_key_file(key_path(keys_dir, version), env_material)
        _write_current_version(keys_dir, version)
        _set_active_cache(env_material, version)
        _upsert_version_row(
            db,
            version=version,
            status=STATUS_ACTIVE,
            source="migrated_from_env",
            activated=True,
        )
        log_action(
            db,
            actor="system",
            action="key_migrated_from_env",
            target="vault:fernet",
            details={"version": version},
        )
        logger.info("encryption key migrated from env to store version=%s", version)
        return version

    version = 1
    material = Fernet.generate_key().decode("ascii")
    _write_key_file(key_path(keys_dir, version), material)
    _write_current_version(keys_dir, version)
    _set_active_cache(material, version)
    _upsert_version_row(
        db,
        version=version,
        status=STATUS_ACTIVE,
        source="generated",
        activated=True,
    )
    log_action(
        db,
        actor="system",
        action="key_generated_initial",
        target="vault:fernet",
        details={"version": version},
    )
    logger.info("encryption key generated initial version=%s", version)
    return version


def _rotation_days(db: Session, settings: Settings) -> int:
    from app.portal_settings_service import get_portal_settings_row

    row = get_portal_settings_row(db)
    if row is not None and getattr(row, "vault_key_rotation_days", None):
        return max(1, int(row.vault_key_rotation_days))
    return max(1, int(settings.vault_key_rotation_days_default))


def get_vault_key_status(db: Session, settings: Settings) -> VaultKeyStatus:
    keys_dir = resolve_keys_dir(settings)
    version = get_active_version() or _read_current_version(keys_dir) or 0
    row = (
        db.query(EncryptionKeyVersion).filter_by(version=version).first()
        if version
        else None
    )
    activated = row.activated_at if row else None
    created = row.created_at if row else None
    ref = activated or created or utcnow()
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    age_days = max(0, (utcnow() - ref).days)
    cadence = _rotation_days(db, settings)
    recommended = age_days >= cadence
    next_due = ref.replace(tzinfo=ref.tzinfo or timezone.utc)
    from datetime import timedelta

    next_due = next_due + timedelta(days=cadence)
    badge = "recommended" if recommended else "ok"
    return VaultKeyStatus(
        version=version,
        created_at=created,
        activated_at=activated,
        age_days=age_days,
        rotation_days=cadence,
        rotation_recommended=recommended,
        next_due_at=next_due,
        status_badge=badge,
        keys_dir=str(keys_dir),
        source=row.source if row else None,
    )


def next_key_version(db: Session, settings: Settings) -> int:
    keys_dir = resolve_keys_dir(settings)
    current = get_active_version() or _read_current_version(keys_dir) or 0
    max_db = db.query(EncryptionKeyVersion.version).order_by(
        EncryptionKeyVersion.version.desc()
    ).first()
    max_ver = max_db[0] if max_db else 0
    # also scan files
    file_max = 0
    for path in keys_dir.glob("fernet_v*.key"):
        digits = "".join(c for c in path.stem if c.isdigit())
        if digits.isdigit():
            file_max = max(file_max, int(digits))
    return max(current, max_ver, file_max) + 1


def backup_active_key_file(settings: Settings) -> Path | None:
    keys_dir = resolve_keys_dir(settings)
    version = get_active_version() or _read_current_version(keys_dir)
    if version is None:
        return None
    src = key_path(keys_dir, version)
    if not src.is_file():
        return None
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    dest = keys_dir / f"{src.name}.bak-pre-rotation-{stamp}"
    shutil.copy2(src, dest)
    try:
        os.chmod(dest, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return dest


def activate_new_key_version(
    db: Session,
    settings: Settings,
    *,
    new_version: int,
    new_material: str,
    old_version: int,
) -> None:
    keys_dir = resolve_keys_dir(settings)
    _write_current_version(keys_dir, new_version)
    now = utcnow()
    old = db.query(EncryptionKeyVersion).filter_by(version=old_version).first()
    if old is not None:
        old.status = STATUS_RETIRED
        old.retired_at = now
    new_row = db.query(EncryptionKeyVersion).filter_by(version=new_version).first()
    if new_row is None:
        new_row = EncryptionKeyVersion(
            version=new_version,
            status=STATUS_ACTIVE,
            created_at=now,
            activated_at=now,
            source="rotated",
        )
        db.add(new_row)
    else:
        new_row.status = STATUS_ACTIVE
        new_row.activated_at = now
        new_row.source = "rotated"
    db.commit()
    _set_active_cache(new_material, new_version)


def write_pending_key(settings: Settings, version: int, material: str) -> Path:
    keys_dir = resolve_keys_dir(settings)
    _ensure_keys_dir(keys_dir)
    path = key_path(keys_dir, version)
    _write_key_file(path, material)
    return path


def delete_key_file(settings: Settings, version: int) -> None:
    path = key_path(resolve_keys_dir(settings), version)
    if path.is_file():
        path.unlink()


def register_pending_version(db: Session, version: int) -> None:
    _upsert_version_row(
        db,
        version=version,
        status=STATUS_PENDING,
        source="rotated",
        activated=False,
    )


def export_active_key_backup(settings: Settings, passphrase: str) -> bytes:
    """Wrap active key material with a passphrase-derived Fernet key (PBKDF2)."""
    phrase = (passphrase or "").strip()
    if len(phrase) < 12:
        raise EncryptionKeyStoreError("passphrase must be at least 12 characters")
    material = get_active_key().encode("utf-8")
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    import base64

    wrap = Fernet(base64.urlsafe_b64encode(kdf.derive(phrase.encode("utf-8"))))
    token = wrap.encrypt(material)
    version = get_active_version() or 0
    header = (
        BACKUP_MAGIC
        + f"version={version}\niterations={PBKDF2_ITERATIONS}\n".encode("ascii")
        + b"salt="
        + salt.hex().encode("ascii")
        + b"\n"
        + b"payload="
    )
    return header + token


def check_rotation_recommended_job(settings: Settings) -> None:
    """Daily watch — logs warning only; never rotates."""
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        status = get_vault_key_status(db, settings)
        if status.rotation_recommended:
            logger.warning(
                "Fernet vault key rotation recommended version=%s age_days=%s cadence_days=%s",
                status.version,
                status.age_days,
                status.rotation_days,
            )
    finally:
        db.close()
