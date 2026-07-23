"""Audit log read, filter, and export (CSV/PDF)."""

import io
from datetime import datetime, timezone

import pandas as pd
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from app.audit import compute_integrity, list_audit_entries
from app.database import get_db
from app.sso_settings import Settings, get_settings
from app.web.flash import base_template_context
from app.web.constants import APP_VERSION
from app.web.templates import render
from app.web.user_context import require_admin

# Router-level admin guard — new routes on this router inherit require_admin.
router = APIRouter(tags=["audit"], dependencies=[Depends(require_admin)])


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


@router.get("/audit")
def audit_page(
    request: Request,
    export: str | None = None,
    date_from: str | None = Query(None, alias="date_from"),
    date_to: str | None = Query(None, alias="date_to"),
    severity: str | None = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    df = _parse_date(date_from)
    dt = _parse_date_end(date_to)
    entries, total = list_audit_entries(db, date_from=df, date_to=dt, severity=severity, limit=200)
    integrity = compute_integrity(db)

    if export == "csv":
        data = [
            {
                "timestamp": e["timestamp"],
                "actor": e["user"],
                "action": e["action"],
                "target": e["target"],
                "severity": e["severity"],
            }
            for e in entries
        ]
        frame = pd.DataFrame(data)
        buf = io.StringIO()
        frame.to_csv(buf, index=False)
        buf.seek(0)
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit-export.csv"},
        )

    if export == "pdf":
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        styles = getSampleStyleSheet()
        story = [
            Paragraph("Bastion Pro — Journaux d'Audit", styles["Title"]),
            Spacer(1, 12),
            Paragraph(
                f"Intégrité: {integrity['score']}% — SHA256: {integrity['hash'][:32]}…",
                styles["Normal"],
            ),
            Spacer(1, 12),
        ]
        table_data = [["Horodatage", "Acteur", "Action", "Cible", "Sévérité"]]
        for e in entries[:100]:
            table_data.append(
                [e["timestamp"], e["user"], e["action"], e["target"], e["severity"]]
            )
        table = Table(table_data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a1e30")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ]
            )
        )
        story.append(table)
        doc.build(story)
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=audit-export.pdf"},
        )

    ctx = base_template_context(
        request,
        settings,
        app_version=APP_VERSION,
        audit_entries=entries,
        integrity=integrity,
        filters={"date_from": date_from or "", "date_to": date_to or ""},
        total_entries=total,
    )
    return render("audit/index.html", **ctx)
