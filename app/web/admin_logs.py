"""Admin logs viewer — audit table, SSE live stream, Docker container logs tab."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import distinct, func
from sqlalchemy.orm import Session

from app.audit import derive_severity, log_action
from app.database import SessionLocal, get_db
from app.models import AuditLog
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.container_logs_settings import get_container_logs_config
from app.web.docker_logs import (
    assert_container_allowed,
    docker_logs_enabled,
    docker_logs_whitelist,
    fetch_container_log_snapshot,
    iter_container_log_follow,
)
from app.web.flash import base_template_context
from app.web.log_masking import format_details_for_display
from app.web.templates import render
from app.web.user_context import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-logs"], dependencies=[Depends(require_admin)])

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


def _client_ip(request: Request) -> str | None:
    from app.request_client_ip import client_ip_from_request

    return client_ip_from_request(request) or None


def _serialize_audit_row(row: AuditLog) -> dict[str, Any]:
    detail_short, detail_full = format_details_for_display(row.details)
    status = None
    if isinstance(row.details, dict) and "status" in row.details:
        status = str(row.details.get("status"))
    elif isinstance(row.details, dict) and "success" in row.details:
        status = "ok" if row.details.get("success") else "error"
    return {
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


def _apply_audit_filters(
    query,
    *,
    action: str | None,
    actor: str | None,
    date_from: datetime | None,
    date_to: datetime | None,
):
    if action:
        query = query.filter(AuditLog.action == action)
    if actor:
        query = query.filter(AuditLog.actor.ilike(f"%{actor.strip()}%"))
    if date_from:
        query = query.filter(AuditLog.created_at >= date_from)
    if date_to:
        query = query.filter(AuditLog.created_at <= date_to)
    return query


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
    query = _apply_audit_filters(
        db.query(AuditLog).order_by(AuditLog.created_at.desc()),
        action=action,
        actor=actor,
        date_from=date_from,
        date_to=date_to,
    )
    total = query.count()
    rows = query.offset(offset).limit(limit).all()

    action_choices = [
        row[0]
        for row in db.query(distinct(AuditLog.action)).order_by(AuditLog.action).all()
        if row[0]
    ]

    entries = [_serialize_audit_row(row) for row in rows]
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
    docker_cfg = get_container_logs_config(db)
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
        docker_logs_enabled=docker_logs_enabled(docker_cfg),
        docker_containers=docker_logs_whitelist(docker_cfg),
        docker_logs_tail_lines=docker_cfg.tail_lines,
        admin_logs_sse_timeout_seconds=settings.admin_logs_sse_timeout_seconds,
    )


@router.get("/admin/logs/stream")
async def admin_logs_stream(
    request: Request,
    action: str | None = None,
    actor: str | None = None,
    date_from: str | None = Query(None, alias="date_from"),
    date_to: str | None = Query(None, alias="date_to"),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    """SSE: push new audit rows matching filters (poll DB). Max duration from settings."""
    df = _parse_date(date_from)
    dt = _parse_date_end(date_to)
    timeout = int(settings.admin_logs_sse_timeout_seconds or 1800)
    timeout = max(5, min(timeout, 86400))

    _db0 = SessionLocal()
    try:
        last_id = int(_db0.query(func.max(AuditLog.id)).scalar() or 0)
    finally:
        _db0.close()

    async def event_gen():
        nonlocal last_id
        started = time.monotonic()
        try:
            while time.monotonic() - started < timeout:
                if await request.is_disconnected():
                    break

                db = SessionLocal()
                try:
                    q = _apply_audit_filters(
                        db.query(AuditLog).filter(AuditLog.id > last_id),
                        action=action or None,
                        actor=actor or None,
                        date_from=df,
                        date_to=dt,
                    )
                    rows = q.order_by(AuditLog.id.asc()).limit(50).all()
                    entries = [_serialize_audit_row(r) for r in rows]
                finally:
                    db.close()

                for entry in entries:
                    last_id = max(last_id, int(entry["id"]))
                    yield f"id: {entry['id']}\ndata: {json.dumps(entry, ensure_ascii=False)}\n\n"
                yield ": keepalive\n\n"
                await asyncio.sleep(1.0)
            yield "event: timeout\ndata: {}\n\n"
        except asyncio.CancelledError:
            logger.debug("audit SSE cancelled")
            raise

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/admin/logs/containers/{name}/logs")
async def admin_container_logs_snapshot(
    name: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Snapshot of last N log lines for a whitelisted container."""
    docker_cfg = get_container_logs_config(db)
    if not docker_logs_enabled(docker_cfg):
        raise HTTPException(status_code=503, detail="Docker logs proxy not configured")
    container = assert_container_allowed(name, docker_cfg)
    text = await fetch_container_log_snapshot(docker_cfg, container)
    log_action(
        db,
        actor=user.email or user.username or "admin",
        action="admin.container_logs.viewed",
        target=container,
        details={"mode": "snapshot", "tail": docker_cfg.tail_lines},
        ip_address=_client_ip(request),
    )
    return {"container": container, "text": text}


@router.get("/admin/logs/containers/{name}/stream")
async def admin_container_logs_stream(
    name: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """SSE tail of a whitelisted container via the read-only Docker proxy."""
    docker_cfg = get_container_logs_config(db)
    if not docker_logs_enabled(docker_cfg):
        raise HTTPException(status_code=503, detail="Docker logs proxy not configured")
    container = assert_container_allowed(name, docker_cfg)
    log_action(
        db,
        actor=user.email or user.username or "admin",
        action="admin.container_logs.viewed",
        target=container,
        details={"mode": "live", "tail": docker_cfg.tail_lines},
        ip_address=_client_ip(request),
    )
    timeout = int(settings.admin_logs_sse_timeout_seconds or 1800)
    timeout = max(5, min(timeout, 86400))

    async def event_gen():
        started = time.monotonic()
        try:
            async for chunk in iter_container_log_follow(docker_cfg, container):
                if await request.is_disconnected():
                    break
                if time.monotonic() - started >= timeout:
                    yield "event: timeout\ndata: {}\n\n"
                    break
                payload = json.dumps({"text": chunk}, ensure_ascii=False)
                yield f"data: {payload}\n\n"
        except asyncio.CancelledError:
            raise
        except HTTPException as exc:
            yield f"event: error\ndata: {json.dumps({'detail': exc.detail})}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
