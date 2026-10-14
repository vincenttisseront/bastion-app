"""Legacy /audit deep links — redirect to the Event Viewer at /admin/logs."""

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query
from fastapi.responses import RedirectResponse

from app.web.user_context import require_admin

# Router-level admin guard — new routes on this router inherit require_admin.
router = APIRouter(tags=["audit"], dependencies=[Depends(require_admin)])


@router.get("/audit")
def audit_page(
    export: str | None = None,
    date_from: str | None = Query(None, alias="date_from"),
    date_to: str | None = Query(None, alias="date_to"),
    severity: str | None = None,
):
    params = {
        "export": export,
        "date_from": date_from,
        "date_to": date_to,
        # Legacy derived severity (success/error/info) is the viewer's result filter.
        "status": severity,
    }
    query = urlencode({k: v for k, v in params.items() if v})
    if not query:
        return RedirectResponse(url="/admin/logs#audit", status_code=302)
    return RedirectResponse(url=f"/admin/logs?{query}", status_code=302)
