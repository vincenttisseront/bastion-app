"""Reportlab PDF renderer for Bastion security compliance reports."""

from __future__ import annotations

import io
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

_NAVY = colors.HexColor("#0a1e30")
_MUTED = colors.HexColor("#5a6a7a")
_OK = colors.HexColor("#1b7a3d")
_WARN = colors.HexColor("#b86a00")
_FAIL = colors.HexColor("#a11a1a")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "BastionTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=16,
            textColor=_NAVY,
            spaceAfter=6,
        ),
        "h2": ParagraphStyle(
            "BastionH2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            textColor=_NAVY,
            spaceBefore=14,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "BastionBody",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            textColor=_NAVY,
            leading=12,
        ),
        "mono": ParagraphStyle(
            "BastionMono",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=8,
            textColor=_NAVY,
            leading=11,
        ),
        "meta": ParagraphStyle(
            "BastionMeta",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=_MUTED,
            alignment=TA_LEFT,
        ),
        "badge_ok": ParagraphStyle(
            "BadgeOk",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=_OK,
        ),
        "badge_warn": ParagraphStyle(
            "BadgeWarn",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=_WARN,
        ),
        "badge_fail": ParagraphStyle(
            "BadgeFail",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=_FAIL,
        ),
        "footer": ParagraphStyle(
            "BastionFooter",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7,
            textColor=_MUTED,
            alignment=TA_CENTER,
        ),
    }


def _badge(label: str, status: str, styles: dict[str, ParagraphStyle]) -> Paragraph:
    key = {
        "ok": "badge_ok",
        "warn": "badge_warn",
        "fail": "badge_fail",
    }.get(status, "body")
    return Paragraph(f"[{status.upper()}] {label}", styles[key])


def _kv_table(rows: list[tuple[str, str]], styles: dict[str, ParagraphStyle]) -> Table:
    data = [
        [Paragraph(str(k), styles["body"]), Paragraph(str(v), styles["mono"])]
        for k, v in rows
    ]
    table = Table(data, colWidths=[70 * mm, 100 * mm])
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.Color(0.85, 0.85, 0.85)),
            ]
        )
    )
    return table


def _section_table(
    headers: list[str],
    rows: list[list[str]],
    styles: dict[str, ParagraphStyle],
    *,
    col_widths: list[float] | None = None,
) -> Table:
    head = [Paragraph(h, styles["body"]) for h in headers]
    body = [
        [Paragraph(str(c), styles["mono"]) for c in row] for row in rows
    ]
    table = Table([head, *body], colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def render_security_compliance_pdf(payload: dict[str, Any]) -> bytes:
    """Build A4 PDF bytes from an aggregated security report payload."""
    styles = _styles()
    buf = io.BytesIO()
    period = payload.get("period") or {}
    meta = payload.get("meta") or {}
    executive = payload.get("executive") or {}
    perimeter = payload.get("perimeter") or {}
    identity = payload.get("identity") or {}

    def _footer(canvas, doc) -> None:
        canvas.saveState()
        text = (
            f"Bastion Pro — Rapport conformité · "
            f"{period.get('label', '')} · page {doc.page}"
        )
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(_MUTED)
        canvas.drawCentredString(A4[0] / 2, 12 * mm, text)
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=20 * mm,
        title="Bastion Pro — Rapport de conformité",
        author="Bastion Portal",
    )
    story: list[Any] = []

    story.append(Paragraph("Bastion Pro — Rapport de conformité sécurité", styles["title"]))
    story.append(
        Paragraph(
            f"Période : <b>{period.get('label', '—')}</b> "
            f"({period.get('start', '')} → {period.get('end', '')}) · "
            f"Généré : {meta.get('generated_at', '—')} · "
            f"Portail : {meta.get('portal_domain', 'portal.example.com')}",
            styles["meta"],
        )
    )
    story.append(Spacer(1, 8))

    # Section 1 — Executive
    story.append(Paragraph("1. Résumé exécutif & score de conformité", styles["h2"]))
    score = int(executive.get("compliance_score") or 0)
    score_status = (
        "ok" if score >= 80 else "warn" if score >= 50 else "fail"
    )
    story.append(_badge(f"Score de conformité : {score}/100", score_status, styles))
    story.append(Spacer(1, 6))
    story.append(
        _kv_table(
            [
                (
                    "Intentions de blocage WAF",
                    str(executive.get("blocked_intents", 0)),
                ),
                (
                    "Blocages exécutés",
                    str(executive.get("blocks_executed", 0)),
                ),
                (
                    "Rejets rate-limit (429 / 24h)",
                    str(executive.get("rate_limit_429_24h", 0)),
                ),
                (
                    "Bans auto comportementaux (actifs)",
                    str(executive.get("auto_bans_active", 0)),
                ),
                (
                    "Runtime hardening",
                    str(executive.get("runtime_status", "loose")),
                ),
                (
                    "is_root / read_only_fs / no_new_privs",
                    f"{executive.get('is_root')} / "
                    f"{executive.get('read_only_fs')} / "
                    f"{executive.get('no_new_privileges')}",
                ),
            ],
            styles,
        )
    )
    for note in executive.get("score_notes") or []:
        story.append(Paragraph(f"• {note}", styles["body"]))

    # Section 2 — Perimeter
    story.append(Paragraph("2. Activité périmétrique & comportementale", styles["h2"]))
    story.append(
        _kv_table(
            [
                (
                    "Événements RelevantOnly (fenêtre audit)",
                    str(perimeter.get("requests_evaluated", 0)),
                ),
                (
                    "Mode portail ModSecurity",
                    str(perimeter.get("portal_mode") or "—"),
                ),
                (
                    "Allowlist IPs",
                    str(perimeter.get("allowlist_ips", 0)),
                ),
                (
                    "Deny nginx (promus)",
                    str(perimeter.get("promoted_deny_count", 0)),
                ),
                (
                    "Auto-bans nginx_limit_req (période)",
                    str(perimeter.get("auto_bans_in_period", 0)),
                ),
            ],
            styles,
        )
    )
    top_rules = perimeter.get("top_rules") or []
    if top_rules:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Top règles ModSecurity / Bastion", styles["body"]))
        story.append(
            _section_table(
                ["Règle", "Libellé", "Count"],
                [
                    [
                        str(r.get("rule_id") or r.get("id") or "—"),
                        str(r.get("label") or r.get("message") or "—")[:48],
                        str(r.get("count") or 0),
                    ]
                    for r in top_rules[:5]
                ],
                styles,
                col_widths=[25 * mm, 120 * mm, 25 * mm],
            )
        )
    else:
        story.append(
            Paragraph("Aucune règle en tête sur la fenêtre d'audit.", styles["meta"])
        )

    # Section 3 — Crypto / identity
    story.append(Paragraph("3. Confiance cryptographique & identité", styles["h2"]))
    ca = identity.get("mtls_ca") or {}
    story.append(
        _kv_table(
            [
                ("CA mTLS", "présent" if ca.get("present") else "absent"),
                ("Empreinte CA (SHA-256)", str(ca.get("fingerprint_sha256") or "—")[:40]),
                (
                    "Apps mTLS actives",
                    f"{identity.get('mtls_active', 0)} / {identity.get('mtls_total', 0)}",
                ),
                (
                    "Admins MFA enrôlés",
                    f"{identity.get('mfa_enrolled', 0)} / {identity.get('mfa_total', 0)} "
                    f"({identity.get('mfa_enrollment_pct', 0)}%)",
                ),
                (
                    "Enforcement MFA",
                    str(identity.get("mfa_enforcement") or "off"),
                ),
                (
                    "Grâce MFA (jours restants)",
                    str(identity.get("mfa_grace_days_left")
                        if identity.get("mfa_grace_days_left") is not None
                        else "—"),
                ),
            ],
            styles,
        )
    )
    clients = identity.get("mtls_clients") or []
    if clients:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Certificats clients mTLS (actifs)", styles["body"]))
        story.append(
            _section_table(
                ["App", "CN", "Statut", "Validité"],
                [
                    [
                        str(c.get("app_name") or "—"),
                        str(c.get("cn") or "—")[:32],
                        str(c.get("status") or "—"),
                        str(c.get("valid_until") or "—")[:19],
                    ]
                    for c in clients[:20]
                ],
                styles,
                col_widths=[40 * mm, 55 * mm, 25 * mm, 50 * mm],
            )
        )

    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            "Document généré automatiquement par Bastion Portal. "
            "KPIs WAF issus du résumé RelevantOnly (télémétrie Bilan). "
            "Ne constitue pas une attestation juridique signée.",
            styles["meta"],
        )
    )

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
