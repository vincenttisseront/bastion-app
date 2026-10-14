"""Audit log export (CSV/PDF) of the rows the Event Viewer shows."""

from __future__ import annotations

import csv
import io
from collections.abc import Sequence
from typing import Any

from fastapi.responses import Response
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

EXPORT_MAX_ROWS = 5000
_PDF_MAX_ROWS = 500
_CSV_COLUMNS = ("timestamp", "event_code", "actor", "action", "target", "ip_address", "result")
# Spreadsheets evaluate cells starting with these as formulas.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def _truncation_note(shown: int, total: int) -> str | None:
    if total <= shown:
        return None
    return f"Export tronqué : {shown} lignes sur {total}. Affinez les filtres."


def build_audit_csv_export(entries: Sequence[dict[str, Any]], *, total: int) -> Response:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_CSV_COLUMNS)
    for entry in entries:
        writer.writerow([_csv_cell(entry.get(col)) for col in _CSV_COLUMNS])
    note = _truncation_note(len(entries), total)
    if note:
        writer.writerow([_csv_cell(note)])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=audit-export.csv",
            "X-Export-Total": str(total),
        },
    )


def build_audit_pdf_export(
    entries: Sequence[dict[str, Any]],
    *,
    total: int,
    integrity: dict[str, Any] | None,
) -> Response:
    shown = list(entries[:_PDF_MAX_ROWS])
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    story: list[Any] = [
        Paragraph("Bastion Pro — Journaux d'Audit", styles["Title"]),
        Spacer(1, 12),
    ]
    if integrity:
        story.append(
            Paragraph(
                f"Intégrité: {integrity['score']}% — SHA256: {integrity['hash'][:32]}…",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 12))
    note = _truncation_note(len(shown), total)
    if note:
        story.append(Paragraph(note, styles["Normal"]))
        story.append(Spacer(1, 12))
    table_data = [["Horodatage", "Acteur", "Action", "Cible", "Résultat"]]
    for e in shown:
        table_data.append(
            [e["timestamp"], e["actor"], e["action"], e["target"], e["result"]]
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
    return Response(
        content=buf.getvalue(),
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=audit-export.pdf",
            "X-Export-Total": str(total),
        },
    )
