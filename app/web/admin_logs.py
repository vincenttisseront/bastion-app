"""Admin logs viewer — Event Viewer-style audit UX + Docker containers tab."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.audit import compute_integrity, log_action
from app.database import SessionLocal, get_db
from app.db.hot_store import hot_read
from app.models import AdminLogsUserPrefs, AuditLog, SavedLogView, utcnow
from app.sso_settings import Settings, get_settings
from app.web.admin_logs_query import (
    DEFAULT_COLUMNS,
    apply_audit_filters,
    count_uncatalogued_types,
    list_admin_log_entries,
    normalize_columns,
    parse_domain_list,
    parse_severity_list,
    parse_status_list,
    serialize_audit_row,
)
from app.audit.event_catalog import DOMAINS, EVENTS, Severity
from app.web.audit_export import build_audit_csv_export, build_audit_pdf_export
from app.web.constants import APP_VERSION
from app.web.container_logs_settings import get_container_logs_config
from app.web.docker_logs import (
    assert_container_allowed,
    docker_logs_enabled,
    docker_logs_whitelist,
    fetch_container_log_snapshot,
    iter_container_log_follow,
)
from app.web.flash import base_template_context, flash_redirect
from app.web.nginx_app_logs import (
    assert_loggable_slug,
    describe_access_log,
    empty_access_log_message,
    iter_access_log_follow,
    list_loggable_apps,
    parse_app_access_text,
    read_access_log_tail,
)
from app.web.templates import render
from app.web.user_context import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-logs"], dependencies=[Depends(require_admin)])

_PAGE_SIZE = 50
_SYSTEM_SECURITY_VIEW = "Sécurité"


def _ensure_system_views(db: Session, user_key: str) -> None:
    """Seed non-deletable default view « Sécurité » (criticité ≥ WARNING)."""
    row = (
        db.query(SavedLogView)
        .filter_by(user_email=user_key, name=_SYSTEM_SECURITY_VIEW)
        .first()
    )
    payload = {
        "severity_min": "WARNING",
        "action": "",
        "actor": "",
        "date_from": "",
        "date_to": "",
        "ip": "",
        "q": "",
        "detail": "",
        "status": [],
        "domain": [],
        "severity": [],
        "event_code": "",
    }
    cols = list(DEFAULT_COLUMNS)
    if row is None:
        db.add(
            SavedLogView(
                user_email=user_key,
                name=_SYSTEM_SECURITY_VIEW,
                filters_json=payload,
                columns_json=cols,
                is_system=True,
            )
        )
        db.commit()
        return
    if not getattr(row, "is_system", False):
        row.is_system = True
        row.filters_json = payload
        db.commit()


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


def _user_key(user) -> str:
    return (user.email or user.username or "admin").strip().lower()


def _get_columns(db: Session, user_key: str) -> list[str]:
    row = db.query(AdminLogsUserPrefs).filter_by(user_email=user_key).first()
    if row and isinstance(row.columns_json, list):
        return normalize_columns(row.columns_json)
    return list(DEFAULT_COLUMNS)


def _list_views(db: Session, user_key: str) -> list[SavedLogView]:
    return (
        db.query(SavedLogView)
        .filter_by(user_email=user_key)
        .order_by(SavedLogView.name.asc())
        .all()
    )


def _filter_dict(
    *,
    action: str | None,
    actor: str | None,
    date_from: str | None,
    date_to: str | None,
    ip: str | None,
    q: str | None,
    detail: str | None,
    status: list[str],
    audit_id: int | None = None,
    event_code: str | None = None,
    domains: list[str] | None = None,
    severities: list[str] | None = None,
    severity_min: str | None = None,
) -> dict[str, Any]:
    return {
        "action": action or "",
        "actor": actor or "",
        "date_from": date_from or "",
        "date_to": date_to or "",
        "ip": ip or "",
        "q": q or "",
        "detail": detail or "",
        "status": status,
        "id": audit_id or "",
        "event_code": event_code or "",
        "domain": domains or [],
        "severity": severities or [],
        "severity_min": severity_min or "",
    }


def _active_chips(filters: dict[str, Any]) -> list[dict[str, str]]:
    chips: list[dict[str, str]] = []
    if filters.get("id"):
        chips.append({"key": "id", "label": f"Entrée #{filters['id']}"})
    if filters.get("action"):
        chips.append({"key": "action", "label": f"Action: {filters['action']}"})
    if filters.get("event_code"):
        chips.append({"key": "event_code", "label": f"Code: {filters['event_code']}"})
    if filters.get("actor"):
        chips.append({"key": "actor", "label": f"Acteur: {filters['actor']}"})
    if filters.get("date_from") or filters.get("date_to"):
        chips.append(
            {
                "key": "dates",
                "label": f"Dates: {filters.get('date_from') or '…'} → {filters.get('date_to') or '…'}",
            }
        )
    if filters.get("ip"):
        chips.append({"key": "ip", "label": f"IP: {filters['ip']}"})
    if filters.get("detail"):
        chips.append({"key": "detail", "label": f"Détail: {filters['detail']}"})
    if filters.get("q"):
        chips.append({"key": "q", "label": f"Recherche: {filters['q']}"})
    for st in filters.get("status") or []:
        chips.append({"key": f"status:{st}", "label": f"Résultat: {st}"})
    for dom in filters.get("domain") or []:
        chips.append({"key": f"domain:{dom}", "label": f"Domaine: {dom}"})
    for sev in filters.get("severity") or []:
        chips.append({"key": f"severity:{sev}", "label": f"Criticité: {sev}"})
    if filters.get("severity_min"):
        chips.append(
            {
                "key": "severity_min",
                "label": f"Criticité ≥ {filters['severity_min']}",
            }
        )
    return chips


@router.get("/admin/logs")
def admin_logs_page(
    request: Request,
    action: str | None = None,
    actor: str | None = None,
    date_from: str | None = Query(None, alias="date_from"),
    date_to: str | None = Query(None, alias="date_to"),
    ip: str | None = None,
    q: str | None = None,
    detail: str | None = None,
    status: list[str] | None = Query(None),
    domain: list[str] | None = Query(None),
    severity: list[str] | None = Query(None),
    severity_min: str | None = None,
    event_code: str | None = None,
    columns: str | None = None,
    view: int | None = None,
    page: int = Query(1, ge=1),
    export: str | None = None,
    audit_id: int | None = Query(None, alias="id", ge=1),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    if export == "csv":
        return build_audit_csv_export(db, date_from=date_from, date_to=date_to)
    if export == "pdf":
        return build_audit_pdf_export(db, date_from=date_from, date_to=date_to)

    user_key = _user_key(user)
    _ensure_system_views(db, user_key)
    if view:
        saved = (
            db.query(SavedLogView)
            .filter_by(id=view, user_email=user_key)
            .first()
        )
        if saved and isinstance(saved.filters_json, dict):
            f = saved.filters_json
            action = action or f.get("action") or None
            actor = actor or f.get("actor") or None
            date_from = date_from or f.get("date_from") or None
            date_to = date_to or f.get("date_to") or None
            ip = ip or f.get("ip") or None
            q = q or f.get("q") or None
            detail = detail or f.get("detail") or None
            event_code = event_code or f.get("event_code") or None
            severity_min = severity_min or f.get("severity_min") or None
            if not status and isinstance(f.get("status"), list):
                status = f.get("status")
            if not domain and isinstance(f.get("domain"), list):
                domain = f.get("domain")
            if not severity and isinstance(f.get("severity"), list):
                severity = f.get("severity")
            if not columns and isinstance(saved.columns_json, list):
                columns = ",".join(str(c) for c in saved.columns_json)

    statuses = parse_status_list(status)
    domains = parse_domain_list(domain)
    severities = parse_severity_list(severity)
    sev_min = (severity_min or "").strip().upper() or None
    if sev_min and sev_min not in {s.value for s in Severity}:
        sev_min = None
    df = _parse_date(date_from)
    dt = _parse_date_end(date_to)
    offset = (page - 1) * _PAGE_SIZE
    # audit_logs is a hot table: without it this page has nothing to show, but
    # it must still say so rather than 500 — and rather than show "no results",
    # which would read as "nothing happened".
    result = hot_read(
        lambda: list_admin_log_entries(
            db,
            action=action or None,
            actor=actor or None,
            date_from=df,
            date_to=dt,
            ip=ip or None,
            q=q or None,
            detail_kw=detail or None,
            status=statuses,
            audit_id=audit_id,
            event_code=event_code or None,
            domains=domains,
            severities=severities,
            severity_min=sev_min,
            limit=_PAGE_SIZE,
            offset=offset,
        ),
        default=None,
        what="audit log entries",
        db=db,
    )
    logs_unavailable = result is None
    entries, total, action_choices = result or ([], 0, [])
    total_pages = max(1, (total + _PAGE_SIZE - 1) // _PAGE_SIZE)
    if columns:
        col_list = normalize_columns([c.strip() for c in columns.split(",") if c.strip()])
    else:
        col_list = _get_columns(db, user_key)
    filters = _filter_dict(
        action=action,
        actor=actor,
        date_from=date_from,
        date_to=date_to,
        ip=ip,
        q=q,
        detail=detail,
        status=statuses,
        audit_id=audit_id,
        event_code=event_code,
        domains=domains,
        severities=severities,
        severity_min=sev_min,
    )
    docker_cfg = get_container_logs_config(db)
    integrity = hot_read(
        lambda: compute_integrity(db), default=None, what="log integrity", db=db
    )
    app_access_apps = list_loggable_apps(db)
    uncatalogued_count = hot_read(
        lambda: count_uncatalogued_types(db, date_from=df, date_to=dt),
        default=None,
        what="uncatalogued event types",
        db=db,
    )
    catalog_codes = sorted(EVENTS.keys())
    ctx = base_template_context(request, settings, APP_VERSION)
    return render(
        "admin/logs.html",
        **ctx,
        entries=entries,
        logs_unavailable=logs_unavailable,
        total=total,
        page=page,
        total_pages=total_pages,
        action_choices=action_choices,
        filters=filters,
        active_chips=_active_chips(filters),
        focus_audit_id=audit_id,
        visible_columns=col_list,
        all_columns=DEFAULT_COLUMNS
        + ["reason", "x_real_ip", "x_forwarded_for", "peer", "resolved", "target"],
        saved_views=_list_views(db, user_key),
        docker_logs_enabled=docker_logs_enabled(docker_cfg),
        docker_containers=docker_logs_whitelist(docker_cfg),
        docker_logs_tail_lines=docker_cfg.tail_lines,
        admin_logs_sse_timeout_seconds=settings.admin_logs_sse_timeout_seconds,
        integrity=integrity,
        app_access_apps=app_access_apps,
        app_access_tail_lines=200,
        uncatalogued_count=uncatalogued_count,
        catalog_domains=sorted(DOMAINS),
        catalog_severities=[s.value for s in Severity],
        catalog_codes=catalog_codes,
    )


@router.get("/admin/logs/stream")
async def admin_logs_stream(
    request: Request,
    action: str | None = None,
    actor: str | None = None,
    date_from: str | None = Query(None, alias="date_from"),
    date_to: str | None = Query(None, alias="date_to"),
    ip: str | None = None,
    q: str | None = None,
    detail: str | None = None,
    status: list[str] | None = Query(None),
    domain: list[str] | None = Query(None),
    severity: list[str] | None = Query(None),
    severity_min: str | None = None,
    event_code: str | None = None,
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    """SSE: push new audit rows matching filters (poll DB)."""
    from app.web.admin_logs_query import entry_matches_live_filters

    statuses = parse_status_list(status)
    domains = parse_domain_list(domain)
    severities = parse_severity_list(severity)
    sev_min = (severity_min or "").strip().upper() or None
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
                    qset = apply_audit_filters(
                        db.query(AuditLog).filter(AuditLog.id > last_id),
                        action=action or None,
                        actor=actor or None,
                        date_from=df,
                        date_to=dt,
                        ip=ip or None,
                        q=q or None,
                        detail_kw=detail or None,
                        event_code=event_code or None,
                    )
                    rows = qset.order_by(AuditLog.id.asc()).limit(50).all()
                    entries = [serialize_audit_row(r) for r in rows]
                    entries = [
                        e
                        for e in entries
                        if entry_matches_live_filters(
                            e,
                            action=action,
                            actor=actor,
                            ip=ip,
                            q=q,
                            detail_kw=detail,
                            status=statuses,
                            event_code=event_code,
                            domains=domains,
                            severities=severities,
                            severity_min=sev_min,
                        )
                    ]
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


@router.post("/admin/logs/prefs/columns")
def admin_logs_save_columns(
    request: Request,
    columns: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    user_key = _user_key(user)
    col_list = normalize_columns([c.strip() for c in columns.split(",") if c.strip()])
    row = db.query(AdminLogsUserPrefs).filter_by(user_email=user_key).first()
    if row is None:
        row = AdminLogsUserPrefs(user_email=user_key, columns_json=col_list)
        db.add(row)
    else:
        row.columns_json = col_list
        row.updated_at = utcnow()
    db.commit()
    response = RedirectResponse(url="/admin/logs#audit", status_code=302)
    flash_redirect(
        response,
        "Colonnes enregistrées.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@router.post("/admin/logs/views")
def admin_logs_save_view(
    request: Request,
    name: str = Form(...),
    filters_json: str = Form("{}"),
    columns: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    user_key = _user_key(user)
    view_name = (name or "").strip()
    if not view_name or view_name.casefold() == "tout":
        raise HTTPException(status_code=400, detail="Nom de vue invalide")
    try:
        filters = json.loads(filters_json or "{}")
        if not isinstance(filters, dict):
            filters = {}
    except json.JSONDecodeError:
        filters = {}
    col_list = normalize_columns([c.strip() for c in columns.split(",") if c.strip()])
    existing = (
        db.query(SavedLogView)
        .filter_by(user_email=user_key, name=view_name)
        .first()
    )
    is_system = view_name == _SYSTEM_SECURITY_VIEW
    if existing:
        if getattr(existing, "is_system", False) and not is_system:
            raise HTTPException(status_code=400, detail="Vue système non modifiable ainsi")
        existing.filters_json = filters
        existing.columns_json = col_list
        existing.is_system = bool(getattr(existing, "is_system", False) or is_system)
    else:
        db.add(
            SavedLogView(
                user_email=user_key,
                name=view_name,
                filters_json=filters,
                columns_json=col_list,
                is_system=is_system,
            )
        )
    db.commit()
    response = RedirectResponse(url="/admin/logs#audit", status_code=302)
    flash_redirect(
        response,
        f"Vue « {view_name} » enregistrée.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@router.post("/admin/logs/views/{view_id}/delete")
def admin_logs_delete_view(
    view_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    user_key = _user_key(user)
    row = (
        db.query(SavedLogView)
        .filter_by(id=view_id, user_email=user_key)
        .first()
    )
    if row and getattr(row, "is_system", False):
        response = RedirectResponse(url="/admin/logs#audit", status_code=302)
        flash_redirect(
            response,
            "La vue système ne peut pas être supprimée.",
            "error",
            settings.vault_portal_internal_token or "dev",
        )
        return response
    if row:
        db.delete(row)
        db.commit()
    response = RedirectResponse(url="/admin/logs#audit", status_code=302)
    flash_redirect(
        response,
        "Vue supprimée.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@router.get("/admin/logs/catalogue")
def admin_logs_catalogue(
    request: Request,
    domain: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    export: str | None = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Read-only event catalogue for SIEM / ops (CSV/JSON export)."""
    rows = list(EVENTS.values())
    if domain:
        d = domain.strip().upper()
        rows = [e for e in rows if e.domain == d]
    if severity:
        s = severity.strip().upper()
        rows = [e for e in rows if e.severity.value == s]
    if q and q.strip():
        term = q.strip().lower()
        rows = [
            e
            for e in rows
            if term in e.code.lower()
            or term in e.label.lower()
            or term in e.title_fr.lower()
            or term in (e.legacy_action or "").lower()
        ]
    rows.sort(key=lambda e: e.code)
    payload = [
        {
            "code": e.code,
            "label": e.label,
            "title_fr": e.title_fr,
            "severity": e.severity.value,
            "domain": e.domain,
            "legacy_action": e.legacy_action or "",
            "ecs_category": list(e.ecs_category),
            "runbook": e.runbook or "",
            "deprecated": e.deprecated,
        }
        for e in rows
    ]
    if export == "json":
        from fastapi.responses import JSONResponse

        return JSONResponse(payload)
    if export == "csv":
        import csv
        import io

        from fastapi.responses import Response

        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=[
                "code",
                "label",
                "title_fr",
                "severity",
                "domain",
                "legacy_action",
                "ecs_category",
                "runbook",
                "deprecated",
            ],
        )
        writer.writeheader()
        for row in payload:
            writer.writerow(
                {
                    **row,
                    "ecs_category": "|".join(row["ecs_category"]),
                }
            )
        return Response(
            content=buf.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": 'attachment; filename="bastion-event-catalogue.csv"'
            },
        )
    ctx = base_template_context(request, settings, APP_VERSION)
    return render(
        "admin/logs_catalogue.html",
        **ctx,
        events=payload,
        domains=sorted(DOMAINS),
        severities=[s.value for s in Severity],
        filters={"domain": domain or "", "severity": severity or "", "q": q or ""},
    )

@router.get("/admin/logs/containers/{name}/logs")
async def admin_container_logs_snapshot(
    name: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
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

@router.get("/admin/logs/apps/{slug}/access")
async def admin_app_access_logs_snapshot(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    tail: int = Query(200, ge=1, le=5000),
):
    safe = assert_loggable_slug(db, slug)
    text = read_access_log_tail(settings, safe, lines=tail)
    meta = describe_access_log(settings, safe)
    log_action(
        db,
        actor=user.email or user.username or "admin",
        action="admin.app_access_logs.viewed",
        target=safe,
        details={
            "mode": "snapshot",
            "tail": tail,
            "empty": not bool(text.strip()),
            "exists": bool(meta.get("exists")),
            "size_bytes": int(meta.get("size_bytes") or 0),
        },
        ip_address=_client_ip(request),
    )
    entries = parse_app_access_text(text) if text.strip() else []
    return {
        "slug": safe,
        "text": text,
        "entries": entries,
        "meta": meta,
        "message": None if text.strip() else empty_access_log_message(settings, safe).rstrip(),
    }


@router.get("/admin/logs/apps/{slug}/stream")
async def admin_app_access_logs_stream(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    tail: int = Query(200, ge=1, le=5000),
):
    safe = assert_loggable_slug(db, slug)
    log_action(
        db,
        actor=user.email or user.username or "admin",
        action="admin.app_access_logs.viewed",
        target=safe,
        details={"mode": "live", "tail": tail},
        ip_address=_client_ip(request),
    )
    timeout = int(settings.admin_logs_sse_timeout_seconds or 1800)
    timeout = max(5, min(timeout, 86400))

    async def event_gen():
        started = time.monotonic()
        try:
            async for chunk in iter_access_log_follow(settings, safe, lines=tail):
                if await request.is_disconnected():
                    break
                if time.monotonic() - started >= timeout:
                    yield "event: timeout\ndata: {}\n\n"
                    break
                entries = parse_app_access_text(chunk)
                payload = json.dumps(
                    {"text": chunk, "entries": entries}, ensure_ascii=False
                )
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
