"""Idea 7 — incident note when an application goes down.

Correlates the failing probe, recent 5xx/upstream errors from the app's nginx
access log and recent WARNING+ audit events. Runs detached from the probe
cycle (its own thread) so a slow model never delays health probes.
Fallback: today's behaviour (probe status on the health page, no summary).
"""

from __future__ import annotations

import logging
import threading
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.llm.insights import STATUS_INFO, generate_insight, latest_insight
from app.models import App, AuditLog, utcnow
from app.sso_settings import Settings, get_settings

logger = logging.getLogger(__name__)

_MAX_PER_CYCLE = 3
_DEDUP_WINDOW = timedelta(minutes=30)

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "maxLength": 800},
        "probable_cause": {"type": "string", "maxLength": 600},
        "confidence": {"type": "string", "enum": ["faible", "moyenne", "elevee"]},
        "evidence": {"type": "array", "items": {"type": "string", "maxLength": 300}, "maxItems": 8},
        "next_steps": {"type": "array", "items": {"type": "string", "maxLength": 300}, "maxItems": 6},
    },
    "required": ["summary", "probable_cause", "confidence", "evidence", "next_steps"],
    "additionalProperties": False,
}

INSTRUCTIONS = (
    "Rédige une courte note d'incident pour une application devenue injoignable "
    "derrière le portail Bastion (reverse proxy nginx). Corrèle la sonde de santé, "
    "les erreurs récentes du journal d'accès nginx (5xx, statut amont, temps de "
    "réponse) et les événements d'audit récents. Donne la cause la plus probable "
    "(amont arrêté, timeout, DNS, certificat, configuration nginx, WAF, "
    "authentification…), les éléments qui la soutiennent et les vérifications à "
    "faire. N'invente aucun fait absent des données."
)


def _access_errors(settings: Settings, slug: str, limit: int = 40) -> list[dict[str, Any]]:
    from app.web.nginx_app_logs import parse_app_access_text, read_access_log_tail

    try:
        text = read_access_log_tail(settings, slug, lines=400)
    except Exception:  # noqa: BLE001 — HTTPException on OSError, missing dir…
        return []
    out: list[dict[str, Any]] = []
    for entry in parse_app_access_text(text):
        status = str(entry.get("status") or "")
        upstream = str(entry.get("upstream_status") or "")
        if not (status.startswith("5") or upstream.startswith("5") or entry.get("auth_err")):
            continue
        out.append({
            "time": entry.get("time_local"),
            "method": entry.get("method"),
            "path": str(entry.get("path") or "")[:200],
            "status": status,
            "upstream_status": upstream,
            "upstream_addr": entry.get("upstream_addr"),
            "request_time": entry.get("request_time"),
            "upstream_response_time": entry.get("upstream_response_time"),
        })
    return out[-limit:]


def _recent_audit(db: Session, minutes: int = 60, limit: int = 30) -> list[dict[str, Any]]:
    since = utcnow() - timedelta(minutes=minutes)
    try:
        rows = (
            db.query(AuditLog)
            .filter(AuditLog.created_at >= since)
            .filter(AuditLog.severity.in_(("WARNING", "ERROR", "CRITICAL")))
            .filter(~AuditLog.action.like("llm.%"))
            .order_by(AuditLog.id.desc())
            .limit(limit)
            .all()
        )
    except Exception:  # noqa: BLE001 — optional context, never fatal
        return []
    return [
        {
            "time": r.created_at.isoformat() if r.created_at else "",
            "code": r.event_code,
            "action": r.action,
            "target": (r.target or "")[:120],
            "severity": r.severity,
        }
        for r in rows
    ]


async def summarize_outage(
    db: Session,
    settings: Settings | None = None,
    *,
    app_id: int,
    previous_status: str | None = None,
    requested_by: str | None = None,
    force: bool = False,
) -> Any:
    settings = settings or get_settings()
    app = db.get(App, app_id)
    if app is None:
        return None
    if not force:
        last = latest_insight(db, "incident_summary", "app", app_id)
        if last is not None and last.created_at and utcnow() - last.created_at < _DEDUP_WINDOW:
            return last
    data = {
        "application": {
            "slug": app.slug,
            "libelle": app.label,
            "mode_acces": app.access_mode,
            "statut_precedent": previous_status,
        },
        "sonde": {
            "statut": app.last_probe_status,
            "code_http": app.last_probe_http_code,
            "latence_ms": app.last_probe_latency_ms,
            "erreur": app.last_probe_error,
            "date": app.last_probe_at.isoformat() if app.last_probe_at else None,
        },
        "erreurs_nginx_recentes": _access_errors(settings, app.slug),
        "audit_recent_warning_plus": _recent_audit(db),
    }
    return await generate_insight(
        db,
        kind="incident_summary",
        subject_type="app",
        subject_id=app_id,
        instructions=INSTRUCTIONS,
        data=data,
        schema=SCHEMA,
        status=STATUS_INFO,
        requested_by=requested_by,
        settings=settings,
        think=True,
    )


async def _summarize_many(db: Session, *, transitions: list[dict[str, Any]]) -> None:
    from app.llm.service import llm_enabled

    settings = get_settings()
    if not llm_enabled(settings, db):
        return
    for item in transitions[:_MAX_PER_CYCLE]:
        await summarize_outage(
            db, settings, app_id=int(item["app_id"]), previous_status=item.get("previous")
        )


def start_outage_summaries(transitions: list[dict[str, Any]]) -> None:
    """Fire-and-forget from the probe cycle. Cheap no-op when the assistant is off."""
    settings = get_settings()
    from app.llm.service import env_allows

    if not transitions or not env_allows(settings):
        return
    from app.llm.features.jobs import run_llm_job

    threading.Thread(
        target=run_llm_job,
        args=(_summarize_many,),
        kwargs={"transitions": list(transitions)},
        name="llm-outage-summary",
        daemon=True,
    ).start()
