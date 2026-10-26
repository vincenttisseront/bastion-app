"""Admin routes for inter-app mTLS connector (#mtls)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.acme.mtls_client_service import (
    mtls_dashboard_payload,
    provision_mtls_client,
    revoke_mtls_client,
)
from app.database import get_db
from app.sso_settings import Settings, get_settings
from app.web.csrf import portal_signing_secret
from app.web.flash import flash_redirect
from app.web.user_context import require_admin

router = APIRouter(tags=["admin-mtls"], dependencies=[Depends(require_admin)])


@router.get("/api/admin/mtls/status")
def admin_mtls_status_api(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    return JSONResponse(mtls_dashboard_payload(db, settings))


@router.post("/admin/security/mtls/provision")
def admin_mtls_provision_post(
    request: Request,
    app_name: str = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    response = RedirectResponse(url="/admin/security#mtls", status_code=302)
    try:
        row = provision_mtls_client(
            db, settings, app_name=app_name, actor=user.email
        )
        flash_redirect(
            response,
            f"Certificat mTLS émis pour {row.app_name} ({row.cn})",
            "success",
            portal_signing_secret(settings),
        )
    except ValueError as exc:
        flash_redirect(
            response,
            str(exc),
            "error",
            portal_signing_secret(settings),
        )
    return response


@router.post("/admin/security/mtls/revoke/{app_name}")
def admin_mtls_revoke_post(
    app_name: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    response = RedirectResponse(url="/admin/security#mtls", status_code=302)
    try:
        row = revoke_mtls_client(
            db, settings, app_name=app_name, actor=user.email
        )
        flash_redirect(
            response,
            f"Accès mTLS révoqué pour {row.app_name}",
            "success",
            portal_signing_secret(settings),
        )
    except ValueError as exc:
        flash_redirect(
            response,
            str(exc),
            "error",
            portal_signing_secret(settings),
        )
    return response
