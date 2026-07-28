"""Admin HTML routes for ACME / Let's Encrypt (public_proxy)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.acme.settings_service import (
    build_acme_live_status,
    get_acme_config,
    list_domain_statuses,
    sync_reconcile_from_sidecar,
    trigger_reconcile,
    update_acme_settings,
)
from app.database import get_db
from app.secret_crypto import encryption_configured
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context, flash_redirect
from app.web.templates import render
from app.web.user_context import require_admin

router = APIRouter(tags=["admin-acme"], dependencies=[Depends(require_admin)])


def _ctx(request: Request, settings: Settings, **extra: Any) -> dict[str, Any]:
    return base_template_context(request, settings, APP_VERSION, **extra)


def _form_bool(value: str | None) -> bool:
    return value in ("on", "true", "1", "yes")


@router.get("/admin/acme")
def admin_acme_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    sync_reconcile_from_sidecar(db, settings)
    cfg = get_acme_config(db)
    domains = list_domain_statuses(db, settings)
    counts = {
        "total": len(domains),
        "ok": sum(1 for d in domains if d.status == "ok"),
        "renew_soon": sum(1 for d in domains if d.status == "renew_soon"),
        "missing": sum(1 for d in domains if d.status in ("missing", "placeholder", "expired")),
    }
    return render(
        "admin/acme.html",
        **_ctx(
            request,
            settings,
            cfg=cfg,
            domains=domains,
            counts=counts,
            encryption_ok=encryption_configured(settings),
        ),
    )


@router.get("/api/admin/acme/status")
def admin_acme_status_api(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    return JSONResponse(build_acme_live_status(db, settings))


@router.post("/admin/acme/settings")
def admin_acme_settings_post(
    request: Request,
    enabled: str | None = Form(None),
    dns_api: str = Form("dns_cf"),
    acme_ca: str = Form("letsencrypt"),
    cf_account_id: str = Form(""),
    cf_zone_id: str = Form(""),
    cf_token: str = Form(""),
    clear_cf_token: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    response = RedirectResponse(url="/admin/acme", status_code=302)
    try:
        update_acme_settings(
            db,
            settings,
            enabled=_form_bool(enabled),
            dns_api=dns_api,
            acme_ca=acme_ca,
            cf_account_id=cf_account_id,
            cf_zone_id=cf_zone_id,
            cf_token=cf_token or None,
            clear_cf_token=_form_bool(clear_cf_token),
            actor=user.email,
        )
        flash_redirect(
            response,
            "Configuration ACME enregistrée (runtime env exporté pour le sidecar).",
            "success",
            settings.vault_portal_internal_token or "dev",
        )
    except ValueError as exc:
        flash_redirect(
            response,
            str(exc),
            "error",
            settings.vault_portal_internal_token or "dev",
        )
    return response


@router.post("/admin/acme/reconcile")
def admin_acme_reconcile_post(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    response = RedirectResponse(url="/admin/acme#acme-logs", status_code=302)
    ok, message = trigger_reconcile(db, settings, actor=user.email)
    flash_redirect(
        response,
        message,
        "success" if ok else "error",
        settings.vault_portal_internal_token or "dev",
    )
    return response
