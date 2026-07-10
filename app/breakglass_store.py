"""Break-glass account password storage (bcrypt)."""

from datetime import datetime, timezone

import bcrypt
from sqlalchemy.orm import Session

from app.models import BreakGlassAccount


def has_active_breakglass_account(db: Session) -> bool:
    """True when at least one break-glass account is active."""
    return (
        db.query(BreakGlassAccount).filter_by(is_active=True).first() is not None
    )


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
    else:
        account = BreakGlassAccount(username=username, hashed_password=hashed)
        db.add(account)
    db.commit()
    db.refresh(account)
    return account


def verify_breakglass_password(db: Session, username: str, plain_password: str) -> bool:
    """Verify a break-glass password."""
    account = db.query(BreakGlassAccount).filter_by(username=username, is_active=True).first()
    if not account:
        return False
    ok = bcrypt.checkpw(plain_password.encode(), account.hashed_password.encode())
    if ok:
        account.last_used_at = datetime.now(timezone.utc)
        db.commit()
    return ok
