"""Dashboard « ligne de passage »: who went through the bastion, hour by hour.

Twenty-four hourly buckets, oldest first, the last one being the current hour.
- allowed: successful sign-ins and application opens (audit log);
- refused: blocked attempts — the same audit filter as the « Tentatives
  bloquées » KPI — plus ModSecurity blocks from the pre-aggregated WAF summary.

Only timestamps are read, so the query stays cheap whatever the volume.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.db.hot_store import hot_read
from app.models import AuditLog, utcnow

HOURS = 24

# A person or a robot got through: sign-in completed or an application opened.
_AUDIT_ALLOWED_FILTER = or_(
    AuditLog.action.in_(
        (
            "app_launch",
            "app.access",
            "oidc_login_otp_success",
        )
    ),
    AuditLog.action.like("%login_success%"),
    AuditLog.action.like("%.login"),
)


def _floor_hour(dt: datetime) -> datetime:
    return dt.replace(minute=0, second=0, microsecond=0)


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _bucket_counts(timestamps: list[datetime], start: datetime) -> list[int]:
    counts = [0] * HOURS
    for ts in timestamps:
        if ts is None:
            continue
        idx = int((_as_utc(ts) - start).total_seconds() // 3600)
        if 0 <= idx < HOURS:
            counts[idx] += 1
    return counts


def _audit_timestamps(db: Session, flt, since: datetime) -> list[datetime] | None:
    return hot_read(
        lambda: [
            row[0]
            for row in db.query(AuditLog.created_at)
            .filter(flt, AuditLog.created_at >= since)
            .all()
        ],
        default=None,
        what="passage series (24h audit)",
        db=db,
    )


def _waf_hourly_blocks(settings: Any) -> list[int] | None:
    """Hourly ModSecurity blocks, aligned on the same 24 hours (oldest first)."""
    if settings is None:
        return None
    try:
        from app.bastion.modsec_audit_aggregator import read_audit_summary

        summary = read_audit_summary(settings)
    except Exception:
        return None
    series = ((summary or {}).get("series") or {}).get("24h") or []
    if not isinstance(series, list) or not series:
        return None
    values = []
    for item in series[-HOURS:]:
        try:
            values.append(int((item or {}).get("blocks") or 0))
        except (TypeError, ValueError, AttributeError):
            values.append(0)
    return [0] * (HOURS - len(values)) + values


def build_passage_series(db: Session, settings: Any = None, *, now: datetime | None = None) -> dict[str, Any]:
    """Return the 24 h passage series, or ``available: False`` when the audit store is down."""
    current = _floor_hour(_as_utc(now or utcnow()))
    start = current - timedelta(hours=HOURS - 1)

    allowed_ts = _audit_timestamps(db, _AUDIT_ALLOWED_FILTER, start)
    from app.web.metrics_service import _AUDIT_BLOCKED_FILTER

    refused_ts = _audit_timestamps(db, _AUDIT_BLOCKED_FILTER, start)
    if allowed_ts is None or refused_ts is None:
        return {"available": False, "hours": [], "allowed_total": None, "refused_total": None}

    allowed = _bucket_counts(allowed_ts, start)
    refused = _bucket_counts(refused_ts, start)
    waf = _waf_hourly_blocks(settings)
    if waf:
        refused = [a + b for a, b in zip(refused, waf, strict=True)]

    hours = [
        {
            "start": (start + timedelta(hours=i)).isoformat(),
            "allowed": allowed[i],
            "refused": refused[i],
        }
        for i in range(HOURS)
    ]
    peak_idx = max(range(HOURS), key=lambda i: refused[i]) if any(refused) else None
    return {
        "available": True,
        "hours": hours,
        "allowed_total": sum(allowed),
        "refused_total": sum(refused),
        "max": max([a + r for a, r in zip(allowed, refused, strict=True)] + [1]),
        "refused_peak_start": hours[peak_idx]["start"] if peak_idx is not None else None,
        "waf_included": bool(waf),
    }
