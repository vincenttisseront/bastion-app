"""Break-glass account password storage (bcrypt)."""

import json
import logging
from datetime import datetime, timezone

import bcrypt
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import BreakGlassAccount

logger = logging.getLogger(__name__)

LEGACY_BREAKGLASS_USERNAME = "admin"
LEGACY_BREAKGLASS_PASSWORD_HASH_KEY = "breakglass_password_hash"


def _decode_setting_value(raw: str | None) -> str | None:
    if raw is None:
        return None
    text_value = raw.strip()
    if not text_value:
        return None
    if text_value.startswith('"'):
        try:
            parsed = json.loads(text_value)
            return str(parsed).strip() or None
        except json.JSONDecodeError:
            return text_value
    return text_value


def _legacy_settings_table_exists(db: Session) -> bool:
    try:
        row = db.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'")
        ).fetchone()
        return row is not None
    except SQLAlchemyError:
        db.rollback()
        return False


def get_legacy_breakglass_password_hash(db: Session) -> str | None:
    """Read bcrypt hash from legacy settings table (awx-playbook portal v1)."""
    if not _legacy_settings_table_exists(db):
        return None
    try:
        row = db.execute(
            text("SELECT value_json FROM settings WHERE key = :key"),
            {"key": LEGACY_BREAKGLASS_PASSWORD_HASH_KEY},
        ).fetchone()
    except SQLAlchemyError:
        logger.warning("legacy break-glass settings lookup failed", exc_info=True)
        db.rollback()
        return None
    if row is None:
        return None
    return _decode_setting_value(row[0])


def legacy_breakglass_initialized(db: Session) -> bool:
    return get_legacy_breakglass_password_hash(db) is not None


def _check_bcrypt_hash(stored_hash: str, plain_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode(), stored_hash.encode())
    except (ValueError, TypeError):
        logger.warning("invalid bcrypt hash format during password verification")
        return False


def migrate_legacy_breakglass_account(db: Session) -> BreakGlassAccount | None:
    """Copy legacy settings hash into breakglass_accounts (username admin)."""
    if db.query(BreakGlassAccount).filter_by(is_active=True).first() is not None:
        return None
    legacy_hash = get_legacy_breakglass_password_hash(db)
    if not legacy_hash:
        return None
    account = BreakGlassAccount(
        username=LEGACY_BREAKGLASS_USERNAME,
        hashed_password=legacy_hash,
        is_active=True,
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    logger.info("migrated legacy break-glass account for user %s", LEGACY_BREAKGLASS_USERNAME)
    return account


def has_active_breakglass_account(db: Session) -> bool:
    """True when a break-glass account exists (new table or legacy settings)."""
    if db.query(BreakGlassAccount).filter_by(is_active=True).first() is not None:
        return True
    return legacy_breakglass_initialized(db)


def create_initial_breakglass_account(
    db: Session, username: str, plain_password: str
) -> BreakGlassAccount:
    """Create the first break-glass account — refuses if one is already active."""
    if has_active_breakglass_account(db):
        raise ValueError("Active break-glass account already exists")
    return set_breakglass_password(db, username, plain_password)


def set_breakglass_password(db: Session, username: str, plain_password: str) -> BreakGlassAccount:
    """Create or update the break-glass account with a bcrypt hash."""
    hashed = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()
    account = db.query(BreakGlassAccount).filter_by(username=username).first()
    if account:
        account.hashed_password = hashed
        account.is_active = True
    else:
        account = BreakGlassAccount(username=username, hashed_password=hashed)
        db.add(account)
    db.commit()
    db.refresh(account)
    return account


def breakglass_account_exists(db: Session, username: str) -> bool:
    """Active break-glass account with this username — audit detail only.

    Lets breakglass.login_failed distinguish an unknown username (scan/probe)
    from a bad password on a real account (compromise attempt / typo).
    """
    return (
        db.query(BreakGlassAccount)
        .filter_by(username=username, is_active=True)
        .first()
        is not None
    )


def verify_breakglass_password(db: Session, username: str, plain_password: str) -> bool:
    """Verify a break-glass password (new table, with legacy settings fallback)."""
    migrate_legacy_breakglass_account(db)

    account = db.query(BreakGlassAccount).filter_by(username=username, is_active=True).first()
    if account:
        ok = _check_bcrypt_hash(account.hashed_password, plain_password)
        if ok:
            account.last_used_at = datetime.now(timezone.utc)
            db.commit()
        return ok

    if username == LEGACY_BREAKGLASS_USERNAME:
        legacy_hash = get_legacy_breakglass_password_hash(db)
        if legacy_hash and _check_bcrypt_hash(legacy_hash, plain_password):
            migrate_legacy_breakglass_account(db)
            return True

    return False
