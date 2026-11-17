"""Storage of LLM outputs, apart from the records they describe.

The raw event / request / report is never modified: an insight row points at
it by ``(subject_type, subject_id)``. Proposals (``status="proposed"``) wait
for an admin decision; nothing here writes security configuration.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.audit import log_action
from app.llm.service import run_task
from app.models import LlmInsight, utcnow
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

STATUS_INFO = "info"
STATUS_PROPOSED = "proposed"
STATUS_ACCEPTED = "accepted"
STATUS_REJECTED = "rejected"

KIND_LABELS: dict[str, str] = {
    "audit_search": "Recherche dans l'audit",
    "waf_explain": "Explication WAF",
    "login_anomaly": "Anomalie de connexion",
    "access_request": "Aide à la décision (demande d'accès)",
    "recertification": "Revue des permissions",
    "oidc_diagnosis": "Diagnostic OIDC",
    "incident_summary": "Résumé d'incident",
    "siem_enrichment": "Enrichissement SIEM",
    "dependency_review": "Synthèse dépendances",
    "test_generation": "Génération de tests",
}


async def generate_insight(
    db: Session,
    *,
    kind: str,
    subject_type: str,
    subject_id: str | int,
    instructions: str,
    data: Any,
    schema: dict[str, Any],
    status: str = STATUS_INFO,
    requested_by: str | None = None,
    settings: Settings | None = None,
    think: bool = False,
) -> LlmInsight | None:
    """Run one LLM task and persist its validated output. ``None`` on any miss."""
    actor = f"admin:{requested_by}" if requested_by else "system:llm"
    result = await run_task(
        kind,
        instructions=instructions,
        data=data,
        schema=schema,
        db=db,
        settings=settings,
        actor=actor,
        think=think,
    )
    if result is None or result.outcome != "ok" or result.value is None:
        return None
    try:
        row = LlmInsight(
            kind=kind,
            subject_type=subject_type,
            subject_id=str(subject_id)[:255],
            status=status,
            payload=result.value,
            model=result.model,
            prompt_sha256=result.prompt_sha256,
            generated_by="llm",
            requested_by=requested_by,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row
    except Exception:
        logger.warning("llm insight %s not stored", kind, exc_info=True)
        db.rollback()
        return None


def latest_insight(
    db: Session, kind: str, subject_type: str, subject_id: str | int
) -> LlmInsight | None:
    try:
        return (
            db.query(LlmInsight)
            .filter(
                LlmInsight.kind == kind,
                LlmInsight.subject_type == subject_type,
                LlmInsight.subject_id == str(subject_id),
            )
            .order_by(LlmInsight.id.desc())
            .first()
        )
    except Exception:
        logger.debug("llm insight lookup failed", exc_info=True)
        return None


def latest_insights_map(
    db: Session, kind: str, subject_type: str, subject_ids: list[str | int]
) -> dict[str, LlmInsight]:
    """Latest insight per subject id (for list pages). Empty on error."""
    ids = [str(s) for s in subject_ids if s is not None]
    if not ids:
        return {}
    try:
        rows = (
            db.query(LlmInsight)
            .filter(
                LlmInsight.kind == kind,
                LlmInsight.subject_type == subject_type,
                LlmInsight.subject_id.in_(ids),
            )
            .order_by(LlmInsight.id.asc())
            .all()
        )
    except Exception:
        logger.debug("llm insight map failed", exc_info=True)
        return {}
    return {row.subject_id: row for row in rows}


def list_insights(
    db: Session, *, kind: str | None = None, status: str | None = None, limit: int = 100
) -> list[LlmInsight]:
    q = db.query(LlmInsight)
    if kind:
        q = q.filter(LlmInsight.kind == kind)
    if status:
        q = q.filter(LlmInsight.status == status)
    return q.order_by(LlmInsight.id.desc()).limit(max(1, min(500, limit))).all()


def decide_insight(
    db: Session,
    insight_id: int,
    *,
    actor: str,
    accepted: bool,
    note: str | None = None,
    ip_address: str | None = None,
) -> LlmInsight | None:
    """Record the human decision on a proposal. Applies nothing by itself."""
    row = db.get(LlmInsight, insight_id)
    if row is None or row.status != STATUS_PROPOSED:
        return None
    row.status = STATUS_ACCEPTED if accepted else STATUS_REJECTED
    row.decided_by = actor
    row.decided_at = utcnow()
    row.decision_note = (note or "").strip()[:1000] or None
    db.commit()
    log_action(
        db,
        actor,
        "llm.insight_decided",
        target=f"llm_insight:{row.id}",
        details={
            "kind": row.kind,
            "subject": f"{row.subject_type}:{row.subject_id}",
            "decision": row.status,
            "model": row.model,
            "prompt_sha256": row.prompt_sha256,
        },
        ip_address=ip_address,
    )
    return row
