"""Admin API — SIEM Syslog TLS collector CA management."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Request, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.request_client_ip import client_ip_from_request
from app.siem import syslog_ca as ca
from app.siem.ca_service import (
    delete_syslog_ca,
    get_ca_api_status,
    install_syslog_ca,
    run_syslog_tls_ca_test,
)
from app.sso_settings import Settings, get_settings
from app.web.user_context import require_admin

router = APIRouter(
    prefix="/api/admin/siem/syslog-tls",
    tags=["admin-siem-syslog-tls"],
    dependencies=[Depends(require_admin)],
)


def _actor(user) -> str:
    return getattr(user, "email", None) or getattr(user, "username", None) or "admin"


@router.get("/ca")
def api_siem_syslog_ca_get(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    del user
    return get_ca_api_status(db, settings)


@router.post("/ca")
async def api_siem_syslog_ca_upload(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    raw = await file.read(ca.MAX_CA_BYTES + 1)
    try:
        status = install_syslog_ca(
            db,
            settings,
            raw=raw,
            filename=file.filename,
            actor=_actor(user),
            ip_address=client_ip_from_request(request),
        )
    except ca.SyslogCaError as exc:
        return JSONResponse(
            {"ok": False, "error": str(exc)},
            status_code=400,
        )
    return {"ok": True, **status}


@router.delete("/ca")
def api_siem_syslog_ca_delete(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    status = delete_syslog_ca(
        db,
        settings,
        actor=_actor(user),
        ip_address=client_ip_from_request(request),
    )
    return {"ok": True, **status}


@router.post("/test")
def api_siem_syslog_tls_test(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    ok, message, lines = run_syslog_tls_ca_test(
        db,
        settings,
        actor=_actor(user),
        ip_address=client_ip_from_request(request),
    )
    return JSONResponse(
        {"ok": ok, "message": message, "lines": lines},
        status_code=200 if ok else 400,
    )
