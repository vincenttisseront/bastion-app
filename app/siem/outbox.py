"""Persistent SIEM outbox — enqueue, drain with backoff, purge with audit."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import SessionLocal
from app.models import AuditLog, SiemOutboxEntry, utcnow
from app.siem.settings_service import (
    action_passes_filter,
    get_siem_config,
    mark_siem_success,
    resolve_webhook_secret,
)
from app.siem.transport import SiemDeliveryError, deliver_entry
from app.sso_settings import Settings, get_settings
from app.web.admin_logs_query import serialize_audit_row

logger = logging.getLogger(__name__)

# Exponential backoff seconds: 1, 5, 30, 120, cap 600 (10 min)
_BACKOFF = (1, 5, 30, 120)


def _backoff_seconds(attempts: int) -> int:
    idx = max(0, min(attempts - 1, len(_BACKOFF) - 1))
    return min(_BACKOFF[idx] if attempts >= 1 else 1, 600)


def queue_size(db: Session) -> int:
    return int(db.query(SiemOutboxEntry).count() or 0)


def try_enqueue_audit(audit_log_id: int, db: Session | None = None) -> None:
    """Enqueue after log_action commit. Optional db reuses caller session (tests)."""
    own = db is None
    session = db or SessionLocal()
    try:
        cfg = get_siem_config(session)
        if not cfg.enabled:
            return
        row = session.query(AuditLog).filter_by(id=audit_log_id).first()
        if row is None:
            return
        if not action_passes_filter(cfg, row.action):
            return
        # Drop oldest if at capacity (before insert), with explicit audit.
        while queue_size(session) >= cfg.retry_max_queue_size:
            oldest = (
                session.query(SiemOutboxEntry)
                .order_by(SiemOutboxEntry.created_at.asc(), SiemOutboxEntry.id.asc())
                .first()
            )
            if oldest is None:
                break
            _drop_entry(session, oldest, reason="queue_full")
        entry = serialize_audit_row(row)
        if isinstance(row.details, (dict, list)):
            from app.web.log_masking import mask_secrets

            entry["detail"] = mask_secrets(row.details)
        session.add(
            SiemOutboxEntry(
                audit_log_id=row.id,
                action=row.action,
                payload_json=entry,
                attempts=0,
                next_attempt_at=utcnow(),
            )
        )
        session.commit()
    except Exception:
        logger.exception("siem enqueue failed audit_id=%s", audit_log_id)
        try:
            session.rollback()
        except Exception:
            pass
    finally:
        if own:
            session.close()


def _drop_entry(db: Session, item: SiemOutboxEntry, *, reason: str) -> None:
    details = {
        "reason": reason,
        "audit_log_id": item.audit_log_id,
        "action": item.action,
        "outbox_id": item.id,
        "attempts": item.attempts,
        "age_seconds": None,
    }
    if item.created_at is not None:
        created = item.created_at
        if created.tzinfo is None:
            from datetime import timezone as _tz

            created = created.replace(tzinfo=_tz.utc)
        details["age_seconds"] = int((utcnow() - created).total_seconds())
    db.delete(item)
    db.commit()
    log_action(
        db,
        actor="system",
        action="siem.forward.dropped",
        target=str(item.audit_log_id),
        details=details,
        forward_to_siem=False,
    )


def purge_stale(db: Session, cfg) -> int:
    from datetime import timezone as _tz

    cutoff = utcnow() - timedelta(minutes=cfg.retry_max_age_minutes)
    # Compare in Python to avoid SQLite naive/aware filter quirks.
    candidates = (
        db.query(SiemOutboxEntry)
        .order_by(SiemOutboxEntry.created_at.asc())
        .limit(200)
        .all()
    )
    n = 0
    for item in candidates:
        created = item.created_at
        if created is None:
            continue
        if created.tzinfo is None:
            created = created.replace(tzinfo=_tz.utc)
        if created >= cutoff:
            continue
        _drop_entry(db, item, reason="max_age")
        n += 1
        if n >= 100:
            break
    return n


def process_outbox_once(
    db: Session | None = None,
    settings: Settings | None = None,
    *,
    limit: int = 25,
    sock_factory=None,
    http_client=None,
) -> dict[str, int]:
    """Drain due outbox rows. Returns counters."""
    own = db is None
    session = db or SessionLocal()
    settings = settings or get_settings()
    stats = {"sent": 0, "failed": 0, "purged": 0, "skipped": 0}
    try:
        cfg = get_siem_config(session)
        stats["purged"] = purge_stale(session, cfg)
        if not cfg.enabled:
            return stats
        if not cfg.active:
            return stats

        secret = resolve_webhook_secret(session, settings) if cfg.protocol == "webhook_https" else None
        now = utcnow()
        due = (
            session.query(SiemOutboxEntry)
            .filter(SiemOutboxEntry.next_attempt_at <= now)
            .order_by(SiemOutboxEntry.next_attempt_at.asc(), SiemOutboxEntry.id.asc())
            .limit(limit)
            .all()
        )
        for item in due:
            payload = item.payload_json if isinstance(item.payload_json, dict) else {}
            try:
                deliver_entry(
                    payload,
                    cfg,
                    secret=secret,
                    sock_factory=sock_factory,
                    http_client=http_client,
                )
                session.delete(item)
                session.commit()
                mark_siem_success(session)
                stats["sent"] += 1
            except SiemDeliveryError as exc:
                item.attempts = int(item.attempts or 0) + 1
                item.last_error = str(exc)[:500]
                item.next_attempt_at = utcnow() + timedelta(
                    seconds=_backoff_seconds(item.attempts)
                )
                session.commit()
                stats["failed"] += 1
            except Exception as exc:
                logger.exception("siem unexpected delivery error")
                item.attempts = int(item.attempts or 0) + 1
                item.last_error = f"{type(exc).__name__}: {exc}"[:500]
                item.next_attempt_at = utcnow() + timedelta(
                    seconds=_backoff_seconds(item.attempts)
                )
                session.commit()
                stats["failed"] += 1
        return stats
    finally:
        if own:
            session.close()


def build_test_entry(*, actor: str = "admin") -> dict[str, Any]:
    return {
        "id": 0,
        "action": "siem.connectivity.test",
        "actor": actor,
        "target": "siem",
        "ip_address": "",
        "severity": "info",
        "status": None,
        "result": "info",
        "detail_short": "connectivity test",
        "detail_full": '{\n  "op": "connectivity_test"\n}',
        "detail": {"op": "connectivity_test"},
        "extras": {},
        "timestamp": utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def run_connectivity_test(
    db: Session,
    settings: Settings,
    *,
    actor: str,
    sock_factory=None,
    http_client=None,
) -> tuple[bool, str]:
    """Send siem.connectivity.test immediately (bypass queue)."""
    cfg = get_siem_config(db)
    if not cfg.active and not cfg.enabled:
        return False, "Forwarder désactivé"
    if cfg.protocol == "syslog_tls" and not cfg.syslog_host:
        return False, "syslog_host manquant"
    if cfg.protocol == "webhook_https" and not cfg.webhook_url.startswith("https://"):
        return False, "webhook_url HTTPS manquant"
    entry = build_test_entry(actor=actor)
    secret = resolve_webhook_secret(db, settings) if cfg.protocol == "webhook_https" else None
    try:
        deliver_entry(
            entry,
            cfg,
            secret=secret,
            sock_factory=sock_factory,
            http_client=http_client,
        )
        mark_siem_success(db)
        log_action(
            db,
            actor=actor,
            action="siem.connectivity.test",
            target="siem",
            details={"protocol": cfg.protocol, "ok": True},
            forward_to_siem=False,
        )
        return True, "Connexion OK — événement de test envoyé"
    except SiemDeliveryError as exc:
        log_action(
            db,
            actor=actor,
            action="siem.connectivity.test",
            target="siem",
            details={"protocol": cfg.protocol, "ok": False, "error": str(exc)[:300]},
            forward_to_siem=False,
        )
        return False, str(exc)
