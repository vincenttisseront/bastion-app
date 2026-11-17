"""Idea 5 — permission review / recertification.

``build_recertification_data`` is deterministic and works without the LLM
(it backs the raw CSV export): every AccessGrant with its last observed use
(``app_launch`` audit events carry ``grant_ids``), dormant flags, critical
roles and the existing excess-permission alerts. The model only adds a
commentary for the audit report. Fallback: the raw report.
"""

from __future__ import annotations

import csv
import io
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session, joinedload

from app.llm.insights import STATUS_INFO, generate_insight
from app.models import AccessGrant, AuditLog, PortalSettings, RbacRole, utcnow
from app.sso_settings import Settings

_SCAN_DAYS = 365
_MAX_LAUNCH_ROWS = 50_000

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "maxLength": 1200},
        "dormant_findings": {"type": "array", "items": {"type": "string", "maxLength": 300}, "maxItems": 15},
        "risky_combinations": {"type": "array", "items": {"type": "string", "maxLength": 300}, "maxItems": 10},
        "recommendations": {"type": "array", "items": {"type": "string", "maxLength": 300}, "maxItems": 10},
    },
    "required": ["summary", "dormant_findings", "risky_combinations", "recommendations"],
    "additionalProperties": False,
}

INSTRUCTIONS = (
    "Rédige la synthèse d'une campagne de recertification des droits d'accès pour "
    "un auditeur : droits dormants (non utilisés depuis le seuil d'inactivité), "
    "cumuls à risque (rôles critiques, droits d'écriture/suppression anciens, "
    "sujets ayant beaucoup d'accès), et recommandations concrètes (révoquer, "
    "réduire le niveau, faire reconfirmer par le responsable). Appuie-toi "
    "uniquement sur les chiffres et lignes fournis ; cite les sujets et ressources."
)


def _subject_label(g: AccessGrant) -> str:
    if g.subject_type == "group":
        return f"groupe:{g.rbac_group.name if g.rbac_group else g.rbac_group_id}"
    return f"user:{g.user_display_cache or g.keycloak_user_id}"


def _resource_label(g: AccessGrant) -> str:
    if g.resource_type == "application":
        return f"app:{g.application.slug if g.application else g.application_id}"
    if g.resource_type == "rbac_role":
        return f"role:{g.rbac_role.name if g.rbac_role else g.rbac_role_id}"
    if g.resource_type == "system_role":
        return f"system_role:{g.system_role}"
    if g.resource_type == "file":
        return f"file:{g.file_id}"
    if g.resource_type == "folder":
        return f"folder:{g.folder_id}"
    return g.resource_type


def _last_use_by_grant(db: Session) -> dict[int, Any]:
    since = utcnow() - timedelta(days=_SCAN_DAYS)
    last: dict[int, Any] = {}
    rows = (
        db.query(AuditLog.created_at, AuditLog.details)
        .filter(AuditLog.action == "app_launch", AuditLog.created_at >= since)
        .order_by(AuditLog.id.desc())
        .limit(_MAX_LAUNCH_ROWS)
        .all()
    )
    for created_at, details in rows:
        for gid in (details or {}).get("grant_ids") or []:
            try:
                key = int(gid)
            except (TypeError, ValueError):
                continue
            if key not in last or (created_at and created_at > last[key]):
                last[key] = created_at
    return last


def build_recertification_data(db: Session) -> dict[str, Any]:
    from app.rbac.governance_service import excess_permission_alerts

    row = db.get(PortalSettings, 1)
    threshold_days = int(getattr(row, "account_inactivity_days", None) or 180)
    cutoff = utcnow() - timedelta(days=threshold_days)
    last_use = _last_use_by_grant(db)
    critical_roles = {r.id for r in db.query(RbacRole).filter(RbacRole.is_critical.is_(True)).all()}
    grants = (
        db.query(AccessGrant)
        .options(
            joinedload(AccessGrant.rbac_group),
            joinedload(AccessGrant.application),
            joinedload(AccessGrant.rbac_role),
        )
        .order_by(AccessGrant.id)
        .all()
    )
    lines: list[dict[str, Any]] = []
    per_subject: dict[str, int] = {}
    for g in grants:
        subject = _subject_label(g)
        per_subject[subject] = per_subject.get(subject, 0) + 1
        used = last_use.get(g.id)
        old_enough = g.granted_at is not None and g.granted_at < cutoff
        trackable = g.resource_type == "application"
        dormant = bool(trackable and old_enough and (used is None or used < cutoff))
        lines.append({
            "grant_id": g.id,
            "subject": subject,
            "resource": _resource_label(g),
            "access_level": g.access_level,
            "granted_at": g.granted_at.date().isoformat() if g.granted_at else "",
            "granted_by": g.granted_by,
            "last_used": used.date().isoformat() if used else "",
            "dormant": dormant,
            "critical_role": bool(g.rbac_role_id in critical_roles),
        })
    heavy = sorted(
        ({"subject": s, "grants": n} for s, n in per_subject.items() if n >= 10),
        key=lambda x: -x["grants"],
    )[:15]
    return {
        "generated_at": utcnow().isoformat(),
        "inactivity_threshold_days": threshold_days,
        "totals": {
            "grants": len(lines),
            "dormant": sum(1 for line in lines if line["dormant"]),
            "critical_role_grants": sum(1 for line in lines if line["critical_role"]),
            "never_used_apps": sum(
                1 for line in lines if line["resource"].startswith("app:") and not line["last_used"]
            ),
        },
        "grants": lines,
        "subjects_with_many_grants": heavy,
        "excess_permission_alerts": excess_permission_alerts(db),
    }


def recertification_csv(data: dict[str, Any]) -> str:
    from app.web.audit_export import _csv_cell

    buf = io.StringIO()
    cols = ["grant_id", "subject", "resource", "access_level", "granted_at", "granted_by",
            "last_used", "dormant", "critical_role"]
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(cols)
    for line in data["grants"]:
        writer.writerow([_csv_cell(line[c]) for c in cols])
    return buf.getvalue()


async def review_permissions(
    db: Session, settings: Settings, *, requested_by: str | None = None
) -> Any:
    data = build_recertification_data(db)
    flagged = [line for line in data["grants"] if line["dormant"] or line["critical_role"]]
    prompt_data = {
        "seuil_inactivite_jours": data["inactivity_threshold_days"],
        "totaux": data["totals"],
        "droits_a_examiner": flagged[:150],
        "sujets_avec_beaucoup_de_droits": data["subjects_with_many_grants"],
        "alertes_permissions_excessives": data["excess_permission_alerts"],
    }
    return await generate_insight(
        db,
        kind="recertification",
        subject_type="report",
        subject_id=utcnow().strftime("%Y-%m-%d"),
        instructions=INSTRUCTIONS,
        data=prompt_data,
        schema=SCHEMA,
        status=STATUS_INFO,
        requested_by=requested_by,
        settings=settings,
        think=True,
    )
