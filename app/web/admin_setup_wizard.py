"""Admin first-boot setup wizard — site identity in DB, not .env."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.request_client_ip import client_ip_from_request
from app.setup_wizard_service import (
    get_setup_status,
    mark_setup_wizard_complete,
    setup_status_dict,
    update_site_identity,
)
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context, flash_redirect
from app.web.templates import render
from app.web.user_context import require_admin

router = APIRouter(tags=["admin-setup-wizard"], dependencies=[Depends(require_admin)])


def _actor(user) -> str:
    return getattr(user, "email", None) or getattr(user, "username", None) or "admin"


@router.get("/admin/setup-wizard")
def setup_wizard_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    status = get_setup_status(db, settings)
    ctx = base_template_context(
        request,
        settings,
        APP_VERSION,
        setup=setup_status_dict(status),
        form_domain=status.portal_domain,
        form_slug=status.default_realm_slug,
        active="setup-wizard",
        user=user,
    )
    return render("admin/setup_wizard.html", **ctx)


@router.post("/admin/setup-wizard/site")
def setup_wizard_save_site(
    request: Request,
    portal_domain: str = Form(...),
    default_realm_slug: str = Form("default"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    response = RedirectResponse(url="/admin/setup-wizard#site", status_code=303)
    try:
        update_site_identity(
            db,
            settings,
            portal_domain=portal_domain,
            default_realm_slug=default_realm_slug,
            actor=_actor(user),
            ip_address=client_ip_from_request(request),
        )
        flash_redirect(
            response,
            "Identité portail enregistrée en base. "
            "Rechargez bastion-nginx pour appliquer le FQDN edge "
            "(exports/bastion-site.env).",
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


@router.post("/admin/setup-wizard/complete")
def setup_wizard_complete(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    try:
        mark_setup_wizard_complete(
            db,
            settings,
            actor=_actor(user),
            ip_address=client_ip_from_request(request),
        )
        response = RedirectResponse(url="/admin/dashboard", status_code=303)
        flash_redirect(
            response,
            "Configuration initiale terminée.",
            "success",
            settings.vault_portal_internal_token or "dev",
        )
        return response
    except ValueError as exc:
        response = RedirectResponse(url="/admin/setup-wizard", status_code=303)
        flash_redirect(
            response,
            str(exc),
            "error",
            settings.vault_portal_internal_token or "dev",
        )
        return response
