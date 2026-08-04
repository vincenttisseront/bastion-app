"""Audit log read — redirects to /admin/logs; CSV/PDF export kept for deep links."""

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.web.audit_export import build_audit_csv_export, build_audit_pdf_export
from app.web.user_context import require_admin

# Router-level admin guard — new routes on this router inherit require_admin.
router = APIRouter(tags=["audit"], dependencies=[Depends(require_admin)])


@router.get("/audit")
def audit_page(
    request: Request,
    export: str | None = None,
    date_from: str | None = Query(None, alias="date_from"),
    date_to: str | None = Query(None, alias="date_to"),
    severity: str | None = None,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    if export == "csv":
        return build_audit_csv_export(
            db, date_from=date_from, date_to=date_to, severity=severity
        )
    if export == "pdf":
        return build_audit_pdf_export(
            db, date_from=date_from, date_to=date_to, severity=severity
        )
    # Page UI moved to /admin/logs#audit (integrity + filters + live stream).
    return RedirectResponse(url="/admin/logs#audit", status_code=302)
