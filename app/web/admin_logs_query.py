"""Query helpers for /admin/logs advanced filters (Event Viewer style)."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from typing import Any

from sqlalchemy import String, cast, distinct, or_
from sqlalchemy.orm import Session

from app.audit import derive_severity
from app.audit.event_catalog import (
    DOMAINS,
    SEVERITY_RANK,
    Severity,
    get_event_by_code,
    historical_severity_from_result,
    resolve_event,
)
from app.models import AuditLog
from app.web.log_masking import format_details_for_display

DEFAULT_COLUMNS = [
    "timestamp",
    "actor",
    "code",
    "action",
    "target",
    "ip",
    "result",
    "detail",
]
OPTIONAL_DETAIL_COLUMNS = (
    "reason",
    "x_real_ip",
    "x_forwarded_for",
    "peer",
    "resolved",
    "miss_family",
)
ALL_COLUMNS = DEFAULT_COLUMNS + list(OPTIONAL_DETAIL_COLUMNS)

_RESULT_VALUES = frozenset({"success", "error", "info"})
_SEVERITY_VALUES = frozenset(s.value for s in Severity)


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


def parse_severity_list(raw: list[str] | str | None) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = [p.strip().upper() for p in raw.split(",") if p.strip()]
    else:
        parts = []
        for item in raw:
            parts.extend(str(item).split(","))
        parts = [p.strip().upper() for p in parts if p.strip()]
    return [p for p in parts if p in _SEVERITY_VALUES]


def parse_domain_list(raw: list[str] | str | None) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = [p.strip().upper() for p in raw.split(",") if p.strip()]
    else:
        parts = []
        for item in raw:
            parts.extend(str(item).split(","))
        parts = [p.strip().upper() for p in parts if p.strip()]
    return [p for p in parts if p in DOMAINS]


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


def effective_catalog_severity(row: AuditLog, result: str) -> tuple[str, bool]:
    """Return (severity, historical). Historical rows lack event_code."""
    raw_code = getattr(row, "event_code", None)
    raw_sev = getattr(row, "severity", None)
    if raw_code:
        if raw_sev:
            return str(raw_sev).upper(), False
        ev = get_event_by_code(str(raw_code))
        if ev is not None:
            return ev.severity.value, False
        return Severity.WARNING.value, False
    return historical_severity_from_result(result).value, True


def serialize_audit_row(row: AuditLog) -> dict[str, Any]:
    from app.audit import normalize_audit_actor

    raw_details = row.details if isinstance(row.details, dict) else {}
    display_actor, details = normalize_audit_actor(row.actor, raw_details)
    detail_short, detail_full = format_details_for_display(
        details,
        target=row.target or "",
        action=row.action or "",
    )
    status = None
    if "status" in details:
        status = str(details.get("status"))
    elif "success" in details:
        status = "ok" if details.get("success") else "error"
    legacy_severity = derive_severity(row.action)
    result = result_bucket(status, legacy_severity)
    catalog_sev, historical = effective_catalog_severity(row, result)
    event_code = (getattr(row, "event_code", None) or "") or ""
    ev = None
    if event_code:
        ev = get_event_by_code(event_code)
        if ev is None and event_code.endswith("-0000"):
            ev = resolve_event(action=row.action, code=event_code)
    extras: dict[str, str] = {}
    for key in OPTIONAL_DETAIL_COLUMNS:
        if key == "target":
            extras["target"] = row.target or ""
            continue
        if key in details and details[key] is not None:
            extras[key] = str(details[key])
    domain = ""
    event_label = ""
    event_title_fr = ""
    runbook = ""
    ecs_category: list[str] = []
    if ev is not None:
        domain = ev.domain
        event_label = ev.label
        event_title_fr = ev.title_fr
        runbook = ev.runbook or ""
        ecs_category = list(ev.ecs_category)
    elif event_code:
        try:
            from app.audit.event_catalog import parse_event_code

            domain = parse_event_code(event_code)[0]
        except ValueError:
            domain = ""
    return {
        "id": row.id,
        "action": row.action,
        "actor": display_actor,
        "target": row.target or "",
        "ip_address": row.ip_address or "",
        "severity": legacy_severity,
        "status": status,
        "result": result,
        "event_code": event_code or None,
        "event_label": event_label,
        "event_title_fr": event_title_fr,
        "catalog_severity": catalog_sev,
        "domain": domain,
        "runbook": runbook,
        "ecs_category": ecs_category,
        "historical": historical,
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
        if isinstance(net, ipaddress.IPv4Network) and net.prefixlen % 8 == 0:
            octets = str(net.network_address).split(".")
            keep = net.prefixlen // 8
            prefix = ".".join(octets[:keep])
            if keep < 4:
                return AuditLog.ip_address.like(f"{prefix}.%")
            return AuditLog.ip_address == str(net.network_address)
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
    event_code: str | None = None,
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
    if event_code and event_code.strip():
        query = query.filter(AuditLog.event_code == event_code.strip().upper())
    clause = _ip_clause(ip or "")
    if clause is not None and "/" not in (ip or ""):
        query = query.filter(clause)
    elif clause is not None and "/" in (ip or ""):
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
        terms = [t for t in q.strip().split() if t]
        for term in terms:
            like = f"%{term}%"
            query = query.filter(
                or_(
                    AuditLog.actor.ilike(like),
                    AuditLog.action.ilike(like),
                    AuditLog.target.ilike(like),
                    AuditLog.ip_address.ilike(like),
                    AuditLog.event_code.ilike(like),
                    detail_text.ilike(like),
                )
            )
    return query


def _matches_severity_filters(
    entry: dict[str, Any],
    *,
    severities: list[str] | None,
    severity_min: str | None,
) -> bool:
    cat = (entry.get("catalog_severity") or "").upper()
    if not cat:
        return False
    if severities and cat not in set(severities):
        return False
    if severity_min:
        min_rank = SEVERITY_RANK.get(Severity(severity_min), 0)
        try:
            rank = SEVERITY_RANK[Severity(cat)]
        except ValueError:
            return False
        if rank < min_rank:
            return False
    return True


def _matches_domain_filter(entry: dict[str, Any], domains: list[str] | None) -> bool:
    if not domains:
        return True
    return (entry.get("domain") or "").upper() in set(domains)


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
    event_code: str | None = None,
    domains: list[str] | None = None,
    severities: list[str] | None = None,
    severity_min: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int, list[str]]:
    statuses = parse_status_list(status)
    domain_list = parse_domain_list(domains)
    sev_list = parse_severity_list(severities)
    sev_min = (severity_min or "").strip().upper() or None
    if sev_min and sev_min not in _SEVERITY_VALUES:
        sev_min = None
    need_python = (
        bool(statuses)
        or bool(domain_list)
        or bool(sev_list)
        or bool(sev_min)
        or (ip and "/" in ip and not _aligned_v4_prefix(ip))
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
        event_code=event_code,
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

    rows = base.limit(5000).all()
    entries = [serialize_audit_row(r) for r in rows]
    if ip and "/" in ip and not _aligned_v4_prefix(ip):
        entries = [e for e in entries if _ip_matches(e.get("ip_address"), ip)]
    if statuses:
        wanted = set(statuses)
        entries = [e for e in entries if e.get("result") in wanted]
    if domain_list:
        entries = [e for e in entries if _matches_domain_filter(e, domain_list)]
    if sev_list or sev_min:
        entries = [
            e
            for e in entries
            if _matches_severity_filters(e, severities=sev_list or None, severity_min=sev_min)
        ]
    total = len(entries)
    page = entries[offset : offset + limit]
    return page, total, action_choices


def count_uncatalogued_types(
    db: Session,
    *,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> int:
    q = db.query(distinct(AuditLog.event_code)).filter(
        AuditLog.event_code.isnot(None),
        AuditLog.event_code.like("%-0000"),
    )
    if date_from:
        q = q.filter(AuditLog.created_at >= date_from)
    if date_to:
        q = q.filter(AuditLog.created_at <= date_to)
    return q.count()


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
    event_code: str | None = None,
    domains: list[str] | None = None,
    severities: list[str] | None = None,
    severity_min: str | None = None,
) -> bool:
    """Client-side parity check for SSE-pushed rows (server already filtered)."""
    if action and entry.get("action") != action:
        return False
    if actor and actor.lower() not in (entry.get("actor") or "").lower():
        return False
    if ip and not _ip_matches(entry.get("ip_address"), ip):
        return False
    if event_code and (entry.get("event_code") or "").upper() != event_code.strip().upper():
        return False
    statuses = parse_status_list(status)
    if statuses and entry.get("result") not in statuses:
        return False
    domain_list = parse_domain_list(domains)
    if domain_list and not _matches_domain_filter(entry, domain_list):
        return False
    sev_list = parse_severity_list(severities)
    sev_min = (severity_min or "").strip().upper() or None
    if sev_min and sev_min not in _SEVERITY_VALUES:
        sev_min = None
    if (sev_list or sev_min) and not _matches_severity_filters(
        entry, severities=sev_list or None, severity_min=sev_min
    ):
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
                str(entry.get("event_code") or ""),
                str(entry.get("detail_full") or ""),
            ]
        ).lower()
        if term not in hay:
            return False
    return True
