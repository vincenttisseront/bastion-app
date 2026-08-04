"""Audit log export (CSV/PDF) + integrity helpers shared with /admin/logs."""

from __future__ import annotations

import io
from datetime import datetime, timezone

import pandas as pd
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from app.audit import compute_integrity, list_audit_entries


def parse_audit_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_audit_date_end(value: str | None) -> datetime | None:
    dt = parse_audit_date(value)
    if dt:
        return dt.replace(hour=23, minute=59, second=59)
    return None


def build_audit_csv_export(
    db: Session,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
    severity: str | None = None,
    limit: int = 200,
) -> StreamingResponse:
    df = parse_audit_date(date_from)
    dt = parse_audit_date_end(date_to)
    entries, _total = list_audit_entries(
        db, date_from=df, date_to=dt, severity=severity, limit=limit
    )
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


def build_audit_pdf_export(
    db: Session,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
    severity: str | None = None,
    limit: int = 200,
) -> StreamingResponse:
    df = parse_audit_date(date_from)
    dt = parse_audit_date_end(date_to)
    entries, _total = list_audit_entries(
        db, date_from=df, date_to=dt, severity=severity, limit=limit
    )
    integrity = compute_integrity(db)
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
