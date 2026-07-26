"""Admin action audit journal — write and read helpers."""

import hashlib
import logging
from datetime import datetime
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import AuditLog

logger = logging.getLogger(__name__)


def log_action(
    db: Session,
    actor: str,
    action: str,
    target: str | None = None,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
    *,
    forward_to_siem: bool = True,
) -> AuditLog | None:
    """Persist an audit entry. Never raises — failures are logged and swallowed.

    After a successful commit, optionally enqueue for SIEM forwarding (same
    single write-path accroche used by Live consumers of AuditLog — no
    duplicated call-site hooks).
    """
    try:
        entry = AuditLog(
            actor=actor,
            action=action,
            target=target,
            details=details,
            ip_address=ip_address,
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
    except SQLAlchemyError:
        logger.exception(
            "audit log write failed (actor=%s action=%s target=%s)",
            actor,
            action,
            target,
        )
        try:
            db.rollback()
        except SQLAlchemyError:
            logger.exception("audit log rollback failed")
        return None

    if forward_to_siem and entry is not None:
        try:
            from app.siem.outbox import try_enqueue_audit

            try_enqueue_audit(entry.id, db=db)
        except Exception:
            logger.exception("siem enqueue hook failed audit_id=%s", entry.id)
    return entry


def derive_severity(action: str) -> str:
    action_lower = action.lower()
    if any(x in action_lower for x in ("error", "failed", "blocked", "denied")):
        if "warn" in action_lower:
            return "warn"
        return "error"
    if any(x in action_lower for x in ("warn", "warning")):
        return "warn"
    if any(
        x in action_lower
        for x in ("success", "login", "created", "updated", "valid", "key_rotation")
    ):
        return "success"
    return "info"


def list_audit_entries(
    db: Session,
    *,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    severity: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    query = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    if date_from:
        query = query.filter(AuditLog.created_at >= date_from)
    if date_to:
        query = query.filter(AuditLog.created_at <= date_to)

    rows = query.all()
    entries: list[dict[str, Any]] = []
    for row in rows:
        sev = derive_severity(row.action)
        if severity and sev != severity:
            continue
        entries.append(
            {
                "id": row.id,
                "action": row.action,
                "target": row.target or "",
                "user": row.actor,
                "time": row.created_at.strftime("%H:%M:%S") if row.created_at else "",
                "timestamp": row.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if row.created_at
                else "",
                "severity": sev,
                "ip_address": row.ip_address,
            }
        )

    total = len(entries)
    return entries[offset : offset + limit], total


def compute_integrity(db: Session) -> dict[str, Any]:
    rows = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    if not rows:
        return {
            "score": 100,
            "ok": True,
            "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }

    chain = hashlib.sha256()
    for row in rows:
        payload = (
            f"{row.id}|{row.actor}|{row.action}|{row.target}|"
            f"{row.created_at.isoformat() if row.created_at else ''}"
        )
        chain.update(payload.encode())
        chain.update(chain.digest())

    final_hash = chain.hexdigest()
    ok = True
    score = 100
    for row in rows:
        if row.details and isinstance(row.details, dict) and row.details.get("tampered"):
            ok = False
            score = 0
            break

    return {"score": score, "ok": ok, "hash": final_hash[:64]}
