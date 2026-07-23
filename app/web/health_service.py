"""Admin health probe routes — manual and summary JSON."""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import get_db
from app.health_probe import (
    compute_health_score,
    compute_status_counts,
    probe_all_enabled_apps,
    probe_and_persist_app,
    probe_row_from_app,
)
from app.models import App
from app.sso_settings import Settings, get_settings
from app.testing_framework.throttle import throttle_retry_after
from app.web.user_context import require_admin

router = APIRouter(tags=["health"], dependencies=[Depends(require_admin)])


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "")


@router.post("/admin/health/probe/{app_id}")
async def probe_single_app(
    app_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    app = db.query(App).filter_by(id=app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    if wait := throttle_retry_after("app_health", app_id, min_interval_seconds=5):
        return JSONResponse(
            {"ok": False, "error": f"Trop de tests — réessayez dans {wait:.0f}s"},
            status_code=429,
        )

    payload = await probe_and_persist_app(db, app)
    log_action(
        db,
        actor=user.email,
        action="health.probe",
        target=app.slug,
        details={"status": payload.get("status"), "http_code": payload.get("http_code")},
        ip_address=_client_ip(request),
    )
    return payload


@router.post("/admin/health/probe-all")
async def probe_all_apps(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    summary = await probe_all_enabled_apps(db)
    log_action(
        db,
        actor=user.email,
        action="health.probe_all",
        target="*",
        details=summary["status_counts"],
        ip_address=_client_ip(request),
    )
    return summary


@router.get("/admin/health/summary")
def health_summary(
    db: Session = Depends(get_db),
    _user=Depends(require_admin),
):
    apps = db.query(App).filter_by(enabled=True).order_by(App.slug).all()
    probes = [probe_row_from_app(app) for app in apps]
    status_counts = compute_status_counts(probes)
    total = len(probes)
    return {
        "status_counts": status_counts,
        "health_score": compute_health_score(status_counts, total),
        "probes": probes,
    }
