"""Admin action audit journal — write and read helpers."""

import hashlib
import logging
from datetime import datetime
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import AuditLog

logger = logging.getLogger(__name__)

# Detail keys that may carry a human-readable identity (preferred over Keycloak sub).
_ACTOR_DETAIL_KEYS = (
    "robotic_username",
    "username",
    "email",
    "preferred_username",
    "actor_email",
    "user_email",
    "identity",
)

# Table label when only a Keycloak subject UUID is known.
OPAQUE_SSO_ACTOR = "utilisateur SSO"


def normalize_audit_actor(
    actor: str | None,
    details: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    """
    Prefer a readable identity for the Acteur column.

    Keycloak ``sub`` UUIDs are moved to ``details.keycloak_user_id`` (supplementary)
    and replaced by email/username from details when available, else
    ``utilisateur SSO``.
    """
    from app.web.user_context import _human_label, looks_like_uuid

    raw = (actor or "").strip() or "unknown"
    out: dict[str, Any] = dict(details) if isinstance(details, dict) else {}
    detail_label = _human_label(*(out.get(k) for k in _ACTOR_DETAIL_KEYS))

    if looks_like_uuid(raw):
        out.setdefault("keycloak_user_id", raw)
        if detail_label:
            return detail_label, out
        return OPAQUE_SSO_ACTOR, out

    return raw, out


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
    display_actor, normalized_details = normalize_audit_actor(actor, details)
    try:
        entry = AuditLog(
            actor=display_actor,
            action=action,
            target=target,
            details=normalized_details or None,
            ip_address=ip_address,
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
    except SQLAlchemyError:
        logger.exception(
            "audit log write failed (actor=%s action=%s target=%s)",
            display_actor,
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
    if any(
        x in action_lower
        for x in (
            "error",
            "failed",
            "blocked",
            "denied",
            "unknown_host",
            "no_app",
            "unregistered",
            "rate_limited",
            "ban.applied",
        )
    ):
        if "warn" in action_lower or "rate_limited" in action_lower:
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

    def _row_to_entry(row: AuditLog) -> dict[str, Any]:
        details = row.details if isinstance(row.details, dict) else {}
        display_actor, _ = normalize_audit_actor(row.actor, details)
        return {
            "id": row.id,
            "action": row.action,
            "target": row.target or "",
            "user": display_actor,
            "time": row.created_at.strftime("%H:%M:%S") if row.created_at else "",
            "timestamp": row.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            if row.created_at
            else "",
            "severity": derive_severity(row.action),
            "ip_address": row.ip_address,
        }

    # Severity is derived in Python — only scan when filtering by it.
    # Dashboard / default path must use SQL LIMIT (full table load → OOM/timeout → 500).
    if severity:
        rows = query.all()
        entries = [e for e in (_row_to_entry(r) for r in rows) if e["severity"] == severity]
        total = len(entries)
        return entries[offset : offset + limit], total

    total = query.count()
    rows = query.offset(max(0, offset)).limit(max(1, min(limit, 500))).all()
    return [_row_to_entry(r) for r in rows], total


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
