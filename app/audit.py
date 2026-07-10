"""Admin action audit journal."""

from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog


def log_action(
    db: Session,
    actor: str,
    action: str,
    target: str | None = None,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor=actor,
        action=action,
        target=target,
        details=details,
        ip_address=ip_address,
    )
    db.add(entry)
    db.commit()
    return entry
