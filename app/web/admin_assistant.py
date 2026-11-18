"""Admin → Assistant IA: on-demand LLM analyses and human decisions.

Every route here is an explicit admin action. Long analyses run as background
tasks in a worker thread (``run_llm_job``); the page redirects at once and the
result shows up on reload. When the assistant is disabled or unavailable the
routes flash a notice and the regular screens keep working unchanged.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Body, Depends, Form, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.audit import admin_actor
from app.database import get_db
from app.llm.features.jobs import run_llm_job
from app.llm.insights import KIND_LABELS, decide_insight, list_insights
from app.llm.service import llm_enabled, llm_public_status
from app.portal_settings_service import ensure_portal_settings
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.csrf import portal_signing_secret
from app.web.flash import base_template_context, flash_i18n
from app.web.templates import render
from app.web.user_context import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-assistant"], dependencies=[Depends(require_admin)])

_PAGE = "/admin/assistant"

STATUS_LABELS = {
    "proposed": "À valider",
    "accepted": "Acceptée",
    "rejected": "Rejetée",
    "info": "Information",
}

ACTIONS = [
    {"url": "/admin/assistant/login-anomalies/scan", "label": "Analyser les connexions (dernière heure)"},
    {"url": "/admin/assistant/recertification", "label": "Revue des permissions"},
    {"url": "/admin/assistant/dependencies", "label": "Synthèse des dépendances"},
    {"url": "/admin/assistant/siem/enrich", "label": "Enrichir les événements SIEM récents"},
]


def _safe_next(value: str | None, default: str = _PAGE) -> str:
    value = (value or "").strip()
    if value.startswith("/admin/") and "//" not in value and "\\" not in value:
        return value
    return default


def _redirect(request: Request, settings: Settings, url: str, msgid: str, level: str, **kw: Any):
    response = RedirectResponse(url=url, status_code=302)
    flash_i18n(request, response, msgid, level, portal_signing_secret(settings), **kw)
    return response


def _queue(
    request: Request,
    background: BackgroundTasks,
    db: Session,
    settings: Settings,
    next_url: str,
    fn,
    **kwargs: Any,
):
    if not llm_enabled(settings, db):
        return _redirect(request, settings, next_url, "Assistant IA désactivé.", "warn")
    background.add_task(run_llm_job, fn, settings=settings, **kwargs)
    return _redirect(
        request, settings, next_url,
        "Analyse IA lancée — rechargez la page dans quelques instants.", "success",
    )


# ── page + decisions ─────────────────────────────────────────────────────────


@router.get("/admin/assistant")
def admin_assistant_page(
    request: Request,
    kind: str = Query(""),
    status: str = Query(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    row = ensure_portal_settings(db, settings)
    insights = list_insights(
        db,
        kind=kind if kind in KIND_LABELS else None,
        status=status if status in STATUS_LABELS else None,
        limit=100,
    )
    ctx = base_template_context(
        request,
        settings,
        APP_VERSION,
        llm=llm_public_status(settings, row),
        insights=insights,
        kind=kind,
        status=status,
        kind_labels=KIND_LABELS,
        status_labels=STATUS_LABELS,
        actions=ACTIONS,
    )
    return render("admin/assistant.html", **ctx)


@router.post("/admin/assistant/insights/{insight_id}/decide")
def admin_assistant_decide(
    request: Request,
    insight_id: int,
    decision: str = Form(...),
    note: str = Form(""),
    next: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    row = decide_insight(
        db,
        insight_id,
        actor=admin_actor(user),
        accepted=decision == "accept",
        note=note,
        ip_address=client_ip_from_request(request),
    )
    url = _safe_next(next)
    if row is None:
        return _redirect(request, settings, url, "Proposition introuvable ou déjà traitée.", "warn")
    msg = "Proposition acceptée." if row.status == "accepted" else "Proposition rejetée."
    return _redirect(request, settings, url, msg, "success")


# ── 1. audit search (interactive: awaited) ───────────────────────────────────


@router.post("/admin/assistant/audit-search")
async def admin_assistant_audit_search(
    request: Request,
    question: str = Form(""),
    save_view: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.llm.features.audit_search import filters_query_string, translate_audit_question

    result = await translate_audit_question(
        db, settings, question, requested_by=admin_actor(user)
    )
    if result is None:
        return _redirect(
            request, settings, "/admin/logs#audit",
            "Assistant indisponible — utilisez les filtres manuels.", "warn",
        )
    filters = result["filters"]
    query = filters_query_string(filters)
    if save_view:
        from app.models import SavedLogView

        user_key = (user.email or user.username or "admin").strip().lower()
        name = ("IA · " + question.strip())[:80]
        existing = db.query(SavedLogView).filter_by(user_email=user_key, name=name).first()
        if existing is None:
            existing = SavedLogView(user_email=user_key, name=name, filters_json={}, columns_json=[])
            db.add(existing)
        existing.filters_json = {**filters, "_generated_by": "llm"}
        db.commit()
    return _redirect(
        request, settings, f"/admin/logs?{query}#audit",
        "Filtres proposés par l'IA : {explanation}", "info",
        explanation=result["explanation"] or "—",
    )


# ── 2. WAF event explanation ─────────────────────────────────────────────────


@router.post("/admin/assistant/waf/explain")
def admin_assistant_waf_explain(
    request: Request,
    background: BackgroundTasks,
    timestamp: str = Form(""),
    client_ip: str = Form(""),
    host: str = Form(""),
    uri: str = Form(""),
    rule_id: str = Form(""),
    all_rule_ids: str = Form(""),
    message: str = Form(""),
    score: str = Form(""),
    blocked: str = Form(""),
    matched_scope_kind: str = Form(""),
    matched_target_name: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    event = {
        "timestamp": timestamp, "client_ip": client_ip, "host": host, "uri": uri,
        "rule_id": rule_id, "all_rule_ids": all_rule_ids, "message": message,
        "score": score, "blocked": blocked in ("1", "true", "True", "on"),
        "matched_scope_kind": matched_scope_kind, "matched_target_name": matched_target_name,
    }
    return _queue(
        request, background, db, settings, "/admin/security/waf#bilan",
        _waf_job, event=event, requested_by=admin_actor(user),
    )


async def _waf_job(db: Session, *, settings: Settings, event: dict[str, Any], requested_by: str) -> None:
    from app.llm.features.waf_explain import explain_waf_event

    await explain_waf_event(db, settings, event, requested_by=requested_by)


@router.post("/admin/assistant/waf/threats")
def admin_assistant_waf_threats(
    request: Request,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Analyse the latest WAF events now (also runs every 10 min on the leader)."""
    return _queue(
        request, background, db, settings, "/admin/security/waf#llm-threats",
        _waf_threats_job, requested_by=admin_actor(user),
    )


async def _waf_threats_job(db: Session, *, settings: Settings, requested_by: str) -> None:
    from app.llm.features.waf_threats import analyse_waf_threats

    await analyse_waf_threats(db, settings, requested_by=requested_by, force=True)


# ── 3. login anomalies (also a leader job) ───────────────────────────────────


@router.post("/admin/assistant/login-anomalies/scan")
def admin_assistant_login_scan(
    request: Request,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    return _queue(
        request, background, db, settings, f"{_PAGE}?kind=login_anomaly",
        _login_job, requested_by=admin_actor(user),
    )


async def _login_job(db: Session, *, settings: Settings, requested_by: str) -> None:
    from app.llm.features.login_anomalies import scan_login_anomalies

    await scan_login_anomalies(db, settings, requested_by=requested_by)


# ── 4. access requests ───────────────────────────────────────────────────────


@router.post("/admin/assistant/access-requests/{request_id}")
def admin_assistant_access_request(
    request: Request,
    request_id: int,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    return _queue(
        request, background, db, settings, "/admin/access-requests?status=pending",
        _access_job, request_id=request_id, requested_by=admin_actor(user),
    )


async def _access_job(db: Session, *, settings: Settings, request_id: int, requested_by: str) -> None:
    from app.llm.features.access_requests import analyze_access_request

    await analyze_access_request(db, settings, request_id=request_id, requested_by=requested_by)


# ── 5. recertification ───────────────────────────────────────────────────────


@router.post("/admin/assistant/recertification")
def admin_assistant_recertification(
    request: Request,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    return _queue(
        request, background, db, settings, f"{_PAGE}?kind=recertification",
        _recert_job, requested_by=admin_actor(user),
    )


async def _recert_job(db: Session, *, settings: Settings, requested_by: str) -> None:
    from app.llm.features.recertification import review_permissions

    await review_permissions(db, settings, requested_by=requested_by)


@router.get("/admin/assistant/recertification.csv")
def admin_assistant_recertification_csv(db: Session = Depends(get_db)):
    """Raw recertification data — works with the assistant off (fallback)."""
    from app.llm.features.recertification import build_recertification_data, recertification_csv

    body = recertification_csv(build_recertification_data(db))
    return Response(
        content="﻿" + body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="recertification-droits.csv"'},
    )


# ── 6. OIDC diagnosis (interactive JSON) ─────────────────────────────────────


@router.post("/admin/assistant/oidc/diagnose")
async def admin_assistant_oidc_diagnose(
    payload: dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.llm.features.oidc_diagnosis import diagnose_oidc_test

    realm_id = payload.get("realm_id")
    insight = await diagnose_oidc_test(
        db,
        settings,
        issuer_url=str(payload.get("issuer_url") or ""),
        client_id=str(payload.get("client_id") or ""),
        checks=payload.get("checks"),
        realm_id=int(realm_id) if isinstance(realm_id, int) else None,
        requested_by=admin_actor(user),
    )
    if insight is None:
        return JSONResponse({"ok": False})
    return JSONResponse({"ok": True, "diagnosis": insight.payload, "generated_by": "llm"})


# ── 7. outage summary (manual; automatic on probe up→down) ───────────────────


@router.post("/admin/assistant/incidents/{app_id}")
def admin_assistant_incident(
    request: Request,
    app_id: int,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    return _queue(
        request, background, db, settings, "/admin/health",
        _incident_job, app_id=app_id, requested_by=admin_actor(user),
    )


async def _incident_job(db: Session, *, settings: Settings, app_id: int, requested_by: str) -> None:
    from app.llm.features.incidents import summarize_outage

    await summarize_outage(db, settings, app_id=app_id, requested_by=requested_by, force=True)


# ── 8. SIEM enrichment (manual; also a leader job) ───────────────────────────


@router.post("/admin/assistant/siem/enrich")
def admin_assistant_siem_enrich(
    request: Request,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    return _queue(request, background, db, settings, f"{_PAGE}?kind=siem_enrichment", _siem_job)


async def _siem_job(db: Session, *, settings: Settings) -> None:
    from app.llm.features.siem_enrichment import enrich_recent_siem_events

    await enrich_recent_siem_events(db, settings)


# ── 9. dependencies ──────────────────────────────────────────────────────────


@router.post("/admin/assistant/dependencies")
def admin_assistant_dependencies(
    request: Request,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    return _queue(
        request, background, db, settings, f"{_PAGE}?kind=dependency_review",
        _deps_job, requested_by=admin_actor(user),
    )


async def _deps_job(db: Session, *, settings: Settings, requested_by: str) -> None:
    from app.llm.features.dependencies import review_dependencies

    await review_dependencies(db, settings, requested_by=requested_by)
