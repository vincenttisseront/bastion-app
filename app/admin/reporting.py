"""Admin routes for security compliance PDF reporting."""

from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.audit import admin_actor
from app.database import get_db
from app.reporting.security_report import generate_and_store_report
from app.sso_settings import Settings, get_settings
from app.web.user_context import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-reporting"], dependencies=[Depends(require_admin)])


@router.post("/admin/security/reporting/export")
def export_compliance_pdf(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    period: Literal["weekly", "monthly"] = Query(default="monthly"),
) -> Response:
    """Generate a Bastion compliance PDF (Bilan export) for the admin."""
    _ = request
    payload, pdf, _path = generate_and_store_report(
        db,
        settings,
        period=period,
        actor=admin_actor(user),
        store=True,
        audit=True,
    )
    stamp = (payload.get("meta") or {}).get("generated_at", "now")
    # ISO → safe filename fragment
    safe = str(stamp).replace(":", "").replace("+", "")[:15]
    filename = f"bastion-compliance-{period}-{safe}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Bastion-Compliance-Score": str(
                (payload.get("executive") or {}).get("compliance_score") or 0
            ),
        },
    )
