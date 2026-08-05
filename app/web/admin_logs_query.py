"""Query helpers for /admin/logs advanced filters (Event Viewer style)."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from typing import Any

from sqlalchemy import String, cast, distinct, or_
from sqlalchemy.orm import Session

from app.audit import derive_severity
from app.models import AuditLog
from app.web.log_masking import format_details_for_display

DEFAULT_COLUMNS = [
    "timestamp",
    "actor",
    "action",
    "ip",
    "result",
    "detail",
]
OPTIONAL_DETAIL_COLUMNS = ("reason", "x_real_ip", "x_forwarded_for", "peer", "resolved", "target")
ALL_COLUMNS = DEFAULT_COLUMNS + list(OPTIONAL_DETAIL_COLUMNS)

_RESULT_VALUES = frozenset({"success", "error", "info"})


def normalize_columns(raw: list[str] | None) -> list[str]:
    cols: list[str] = []
    seen: set[str] = set()
    for c in raw or []:
        key = str(c).strip()
        if key in ALL_COLUMNS and key not in seen:
            seen.add(key)
            cols.append(key)
    if "timestamp" not in seen:
        cols.insert(0, "timestamp")
    if "action" not in seen:
        cols.append("action")
    return cols or list(DEFAULT_COLUMNS)


def parse_status_list(raw: list[str] | str | None) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.split(",") if p.strip()]
    else:
        parts = []
        for item in raw:
            parts.extend(str(item).split(","))
        parts = [p.strip() for p in parts if p.strip()]
    return [p for p in parts if p in _RESULT_VALUES]


def result_bucket(status: str | None, severity: str | None) -> str:
    """Map row status/severity to success|error|info (UI filter vocabulary)."""
    st = (status or "").strip().lower()
    sev = (severity or "info").strip().lower()
    if st in ("error", "err", "fail", "failed") or sev == "error":
        return "error"
    if st in ("warn", "warning") or sev == "warn":
        return "error"
    if st in ("ok", "success") or sev == "success":
        return "success"
    return "info"


def serialize_audit_row(row: AuditLog) -> dict[str, Any]:
    from app.audit import normalize_audit_actor

    raw_details = row.details if isinstance(row.details, dict) else {}
    display_actor, details = normalize_audit_actor(row.actor, raw_details)
    detail_short, detail_full = format_details_for_display(details)
    status = None
    if "status" in details:
        status = str(details.get("status"))
    elif "success" in details:
        status = "ok" if details.get("success") else "error"
    severity = derive_severity(row.action)
    extras: dict[str, str] = {}
    for key in OPTIONAL_DETAIL_COLUMNS:
        if key == "target":
            extras["target"] = row.target or ""
            continue
        if key in details and details[key] is not None:
            extras[key] = str(details[key])
    return {
        "id": row.id,
        "action": row.action,
        "actor": display_actor,
        "target": row.target or "",
        "ip_address": row.ip_address or "",
        "severity": severity,
        "status": status,
        "result": result_bucket(status, severity),
        "detail_short": detail_short,
        "detail_full": detail_full,
        "extras": extras,
        "timestamp": row.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        if row.created_at
        else "",
    }


def _ip_clause(ip_filter: str):
    raw = (ip_filter or "").strip()
    if not raw:
        return None
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return AuditLog.ip_address == "__invalid_cidr__"
        # Prefix match for common IPv4 aligned prefixes; else exact membership checked later.
        if isinstance(net, ipaddress.IPv4Network) and net.prefixlen % 8 == 0:
            octets = str(net.network_address).split(".")
            keep = net.prefixlen // 8
            prefix = ".".join(octets[:keep])
            if keep < 4:
                return AuditLog.ip_address.like(f"{prefix}.%")
            return AuditLog.ip_address == str(net.network_address)
        # Non-aligned: defer to Python filter (broad SQL fetch via IS NOT NULL)
        return AuditLog.ip_address.isnot(None)
    return or_(AuditLog.ip_address == raw, AuditLog.ip_address.ilike(f"{raw}%"))


def _ip_matches(ip: str | None, ip_filter: str) -> bool:
    raw = (ip_filter or "").strip()
    if not raw:
        return True
    value = (ip or "").strip()
    if not value:
        return False
    if "/" in raw:
        try:
            return ipaddress.ip_address(value) in ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return False
    return value == raw or value.startswith(raw)


def apply_audit_filters(
    query,
    *,
    action: str | None = None,
    actor: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    ip: str | None = None,
    q: str | None = None,
    detail_kw: str | None = None,
    audit_id: int | None = None,
):
    if audit_id is not None:
        query = query.filter(AuditLog.id == int(audit_id))
    if action:
        query = query.filter(AuditLog.action == action)
    if actor:
        query = query.filter(AuditLog.actor.ilike(f"%{actor.strip()}%"))
    if date_from:
        query = query.filter(AuditLog.created_at >= date_from)
    if date_to:
        query = query.filter(AuditLog.created_at <= date_to)
    clause = _ip_clause(ip or "")
    if clause is not None and "/" not in (ip or ""):
        query = query.filter(clause)
    elif clause is not None and "/" in (ip or ""):
        # Aligned prefix already in clause; non-aligned uses not-null then Python filter.
        try:
            net = ipaddress.ip_network((ip or "").strip(), strict=False)
            if isinstance(net, ipaddress.IPv4Network) and net.prefixlen % 8 == 0:
                query = query.filter(clause)
            else:
                query = query.filter(AuditLog.ip_address.isnot(None))
        except ValueError:
            query = query.filter(AuditLog.ip_address == "__invalid_cidr__")
    detail_text = cast(AuditLog.details, String)
    if detail_kw and detail_kw.strip():
        kw = detail_kw.strip()
        query = query.filter(detail_text.ilike(f"%{kw}%"))
    if q and q.strip():
        term = q.strip()
        like = f"%{term}%"
        query = query.filter(
            or_(
                AuditLog.actor.ilike(like),
                AuditLog.action.ilike(like),
                AuditLog.target.ilike(like),
                AuditLog.ip_address.ilike(like),
                detail_text.ilike(like),
            )
        )
    return query


def list_admin_log_entries(
    db: Session,
    *,
    action: str | None = None,
    actor: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    ip: str | None = None,
    q: str | None = None,
    detail_kw: str | None = None,
    status: list[str] | None = None,
    audit_id: int | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int, list[str]]:
    statuses = parse_status_list(status)
    need_python = bool(statuses) or (
        ip and "/" in ip and not _aligned_v4_prefix(ip)
    )

    base = apply_audit_filters(
        db.query(AuditLog).order_by(AuditLog.created_at.desc()),
        action=action,
        actor=actor,
        date_from=date_from,
        date_to=date_to,
        ip=ip,
        q=q,
        detail_kw=detail_kw,
        audit_id=audit_id,
    )

    action_choices = [
        row[0]
        for row in db.query(distinct(AuditLog.action)).order_by(AuditLog.action).all()
        if row[0]
    ]

    if not need_python:
        total = base.count()
        rows = base.offset(offset).limit(limit).all()
        return [serialize_audit_row(r) for r in rows], total, action_choices

    # Status / non-aligned CIDR: filter in Python (admin-scale volumes).
    rows = base.limit(5000).all()
    entries = [serialize_audit_row(r) for r in rows]
    if ip and "/" in ip and not _aligned_v4_prefix(ip):
        entries = [e for e in entries if _ip_matches(e.get("ip_address"), ip)]
    if statuses:
        wanted = set(statuses)
        entries = [e for e in entries if e.get("result") in wanted]
    total = len(entries)
    page = entries[offset : offset + limit]
    return page, total, action_choices


def _aligned_v4_prefix(ip_filter: str) -> bool:
    try:
        net = ipaddress.ip_network(ip_filter.strip(), strict=False)
    except ValueError:
        return False
    return isinstance(net, ipaddress.IPv4Network) and net.prefixlen % 8 == 0


def entry_matches_live_filters(
    entry: dict[str, Any],
    *,
    action: str | None,
    actor: str | None,
    ip: str | None,
    q: str | None,
    detail_kw: str | None,
    status: list[str] | None,
) -> bool:
    """Client-side parity check for SSE-pushed rows (server already filtered)."""
    if action and entry.get("action") != action:
        return False
    if actor and actor.lower() not in (entry.get("actor") or "").lower():
        return False
    if ip and not _ip_matches(entry.get("ip_address"), ip):
        return False
    statuses = parse_status_list(status)
    if statuses and entry.get("result") not in statuses:
        return False
    if detail_kw:
        blob = (entry.get("detail_full") or "") + json.dumps(entry.get("extras") or {})
        if detail_kw.lower() not in blob.lower():
            return False
    if q:
        term = q.lower()
        hay = " ".join(
            [
                str(entry.get("actor") or ""),
                str(entry.get("action") or ""),
                str(entry.get("target") or ""),
                str(entry.get("ip_address") or ""),
                str(entry.get("detail_full") or ""),
            ]
        ).lower()
        if term not in hay:
            return False
    return True
