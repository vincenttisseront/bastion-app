"""Idea 8 — SIEM enrichment, asynchronous and never blocking delivery.

The raw audit event is forwarded exactly as today (the outbox drain never
looks at the LLM). Afterwards, a leader job takes recent WARNING+ events,
asks the model for a summary / category / suggested severity, stores that
in ``llm_insights`` and emits a *separate* ``llm.siem_enrichment`` audit
event that references the original id. The original ``AuditLog`` row and
its outbox payload are never modified. Fallback: events sent unenriched.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.audit import log_action
from app.llm.insights import latest_insights_map
from app.llm.service import run_task
from app.models import AuditLog, LlmInsight, utcnow
from app.sso_settings import Settings, get_settings

_WINDOW = timedelta(minutes=15)
_BATCH = 10
_CATEGORIES = [
    "authentification", "acces", "configuration", "intrusion", "disponibilite",
    "donnees", "conformite", "autre",
]
_SEVERITIES = ["INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL"]

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "events": {
            "type": "array",
            "maxItems": _BATCH,
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "summary": {"type": "string", "maxLength": 300},
                    "category": {"type": "string", "enum": _CATEGORIES},
                    "suggested_severity": {"type": "string", "enum": _SEVERITIES},
                },
                "required": ["id", "summary", "category", "suggested_severity"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["events"],
    "additionalProperties": False,
}

INSTRUCTIONS = (
    "Pour chaque événement d'audit du portail Bastion, écris un résumé d'une "
    "phrase lisible par un analyste SOC, une catégorie et une gravité suggérée "
    "(qui peut différer de la gravité du catalogue si le contexte le justifie). "
    "Reprends exactement l'identifiant 'id' de chaque événement."
)


def _siem_enabled(db: Session) -> bool:
    try:
        from app.siem.settings_service import ensure_siem_settings

        return bool(ensure_siem_settings(db).enabled)
    except Exception:  # noqa: BLE001 — SIEM off or misconfigured: no enrichment
        return False


def _candidates(db: Session) -> list[AuditLog]:
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.created_at >= utcnow() - _WINDOW)
        .filter(AuditLog.severity.in_(("WARNING", "ERROR", "CRITICAL")))
        .filter(~AuditLog.action.like("llm.%"))
        .order_by(AuditLog.id.desc())
        .limit(_BATCH * 5)
        .all()
    )
    done = latest_insights_map(db, "siem_enrichment", "audit_log", [r.id for r in rows])
    return [r for r in rows if str(r.id) not in done][:_BATCH]


async def enrich_recent_siem_events(db: Session, settings: Settings | None = None) -> int:
    """Return the number of enrichment events emitted. 0 when off or nothing to do."""
    from app.llm.service import llm_enabled
    from app.web.log_masking import mask_secrets

    settings = settings or get_settings()
    if not llm_enabled(settings, db) or not _siem_enabled(db):
        return 0
    rows = _candidates(db)
    if not rows:
        return 0
    by_id = {r.id: r for r in rows}
    data = [
        {
            "id": r.id,
            "code": r.event_code,
            "action": r.action,
            "gravite_catalogue": r.severity,
            "acteur": r.actor,
            "cible": (r.target or "")[:200],
            "ip": r.ip_address,
            "details": mask_secrets(r.details),
            "date": r.created_at.isoformat() if r.created_at else "",
        }
        for r in rows
    ]
    result = await run_task(
        "siem_enrichment", instructions=INSTRUCTIONS, data=data, schema=SCHEMA,
        db=db, settings=settings,
    )
    if result is None or result.outcome != "ok" or not result.value:
        return 0
    emitted = 0
    for item in result.value.get("events") or []:
        original = by_id.get(item.get("id"))
        if original is None:
            continue
        enrichment = {
            "summary": item["summary"],
            "category": item["category"],
            "suggested_severity": item["suggested_severity"],
        }
        db.add(LlmInsight(
            kind="siem_enrichment",
            subject_type="audit_log",
            subject_id=str(original.id),
            status="info",
            payload=enrichment,
            model=result.model,
            prompt_sha256=result.prompt_sha256,
        ))
        db.commit()
        log_action(
            db,
            "system:llm",
            "llm.siem_enrichment",
            target=f"audit_log:{original.id}",
            details={
                "enriches_audit_id": original.id,
                "enriches_event_code": original.event_code,
                "generated_by": "llm",
                "model": result.model,
                **enrichment,
            },
            forward_to_siem=True,
        )
        emitted += 1
    return emitted


async def siem_enrichment_job_body(db: Session) -> None:
    await enrich_recent_siem_events(db)
