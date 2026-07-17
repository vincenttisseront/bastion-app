"""Admin logs viewer — paginated audit_logs with filters and secret masking."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import distinct
from sqlalchemy.orm import Session

from app.audit import derive_severity
from app.database import get_db
from app.models import AuditLog
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context
from app.web.log_masking import format_details_for_display
from app.web.templates import render
from app.web.user_context import require_admin

router = APIRouter(tags=["admin-logs"])

_PAGE_SIZE = 50


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _parse_date_end(value: str | None) -> datetime | None:
    dt = _parse_date(value)
    if dt:
        return dt.replace(hour=23, minute=59, second=59)
    return None


def list_admin_log_entries(
    db: Session,
    *,
    action: str | None = None,
    actor: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    limit: int = _PAGE_SIZE,
    offset: int = 0,
) -> tuple[list[dict], int, list[str]]:
    query = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    if action:
        query = query.filter(AuditLog.action == action)
    if actor:
        query = query.filter(AuditLog.actor.ilike(f"%{actor.strip()}%"))
    if date_from:
        query = query.filter(AuditLog.created_at >= date_from)
    if date_to:
        query = query.filter(AuditLog.created_at <= date_to)

    total = query.count()
    rows = query.offset(offset).limit(limit).all()

    action_choices = [
        row[0]
        for row in db.query(distinct(AuditLog.action)).order_by(AuditLog.action).all()
        if row[0]
    ]

    entries: list[dict] = []
    for row in rows:
        detail_short, detail_full = format_details_for_display(row.details)
        status = None
        if isinstance(row.details, dict) and "status" in row.details:
            status = str(row.details.get("status"))
        elif isinstance(row.details, dict) and "success" in row.details:
            status = "ok" if row.details.get("success") else "error"
        entries.append(
            {
                "id": row.id,
                "action": row.action,
                "actor": row.actor,
                "target": row.target or "",
                "ip_address": row.ip_address or "",
                "severity": derive_severity(row.action),
                "status": status,
                "detail_short": detail_short,
                "detail_full": detail_full,
                "timestamp": row.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if row.created_at
                else "",
            }
        )
    return entries, total, action_choices


@router.get("/admin/logs")
def admin_logs_page(
    request: Request,
    action: str | None = None,
    actor: str | None = None,
    date_from: str | None = Query(None, alias="date_from"),
    date_to: str | None = Query(None, alias="date_to"),
    page: int = Query(1, ge=1),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    df = _parse_date(date_from)
    dt = _parse_date_end(date_to)
    offset = (page - 1) * _PAGE_SIZE
    entries, total, action_choices = list_admin_log_entries(
        db,
        action=action or None,
        actor=actor or None,
        date_from=df,
        date_to=dt,
        limit=_PAGE_SIZE,
        offset=offset,
    )
    total_pages = max(1, (total + _PAGE_SIZE - 1) // _PAGE_SIZE)
    ctx = base_template_context(request, settings, APP_VERSION)
    return render(
        "admin/logs.html",
        **ctx,
        entries=entries,
        total=total,
        page=page,
        total_pages=total_pages,
        action_choices=action_choices,
        filters={
            "action": action or "",
            "actor": actor or "",
            "date_from": date_from or "",
            "date_to": date_to or "",
        },
    )
