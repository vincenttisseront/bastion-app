"""Admin branding settings — public portal identity anonymization."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.branding import (
    clear_branding_asset,
    ensure_branding_dir,
    get_branding_settings,
    save_branding_favicon,
    save_branding_logo,
    update_branding_settings,
)
from app.database import get_db
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings
from app.web.app_logos import LogoValidationError
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context, flash_redirect
from app.web.templates import render
from app.web.user_context import require_admin

router = APIRouter(tags=["admin-branding"], dependencies=[Depends(require_admin)])


def _actor(user) -> str:
    return getattr(user, "email", None) or getattr(user, "username", None) or "admin"


@router.get("/admin/branding")
def admin_branding_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    ensure_branding_dir(settings)
    branding = get_branding_settings(db)
    ctx = base_template_context(request, settings, APP_VERSION, branding=branding)
    return render("admin/branding.html", **ctx)


@router.post("/admin/branding")
async def admin_branding_save(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    company_name: str = Form(""),
    page_title: str = Form(""),
    accent_color: str = Form("#10b981"),
    secondary_color: str = Form("#059669"),
    highlight_color: str = Form("#34d399"),
    default_theme: str = Form("dark"),
    welcome_text: str = Form(""),
    footer_text: str = Form(""),
    support_contact: str = Form(""),
    show_product_branding: str | None = Form(None),
):
    token = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/admin/branding", status_code=302)
    try:
        update_branding_settings(
            db,
            actor=_actor(user),
            ip_address=client_ip_from_request(request),
            company_name=company_name,
            page_title=page_title,
            accent_color=accent_color,
            secondary_color=secondary_color,
            highlight_color=highlight_color,
            default_theme=default_theme,
            welcome_text=welcome_text,
            footer_text=footer_text,
            support_contact=support_contact,
            show_product_branding=show_product_branding is not None,
        )
        flash_redirect(response, "Branding enregistré.", "success", token)
    except ValueError as exc:
        flash_redirect(response, str(exc), "error", token)
    return response


@router.post("/admin/branding/logo")
async def admin_branding_logo_upload(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    file: UploadFile = File(...),
):
    token = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/admin/branding", status_code=302)
    raw = await file.read()
    try:
        save_branding_logo(
            db,
            raw,
            actor=_actor(user),
            ip_address=client_ip_from_request(request),
            settings=settings,
        )
        flash_redirect(response, "Logo mis à jour.", "success", token)
    except LogoValidationError as exc:
        flash_redirect(response, str(exc), "error", token)
    return response


@router.post("/admin/branding/favicon")
async def admin_branding_favicon_upload(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    file: UploadFile = File(...),
):
    token = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/admin/branding", status_code=302)
    raw = await file.read()
    try:
        save_branding_favicon(
            db,
            raw,
            actor=_actor(user),
            ip_address=client_ip_from_request(request),
            settings=settings,
        )
        flash_redirect(response, "Favicon mis à jour.", "success", token)
    except LogoValidationError as exc:
        flash_redirect(response, str(exc), "error", token)
    return response


@router.post("/admin/branding/logo/delete")
async def admin_branding_logo_delete(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    token = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/admin/branding", status_code=302)
    clear_branding_asset(
        db,
        kind="logo",
        actor=_actor(user),
        ip_address=client_ip_from_request(request),
        settings=settings,
    )
    flash_redirect(response, "Logo supprimé.", "success", token)
    return response


@router.post("/admin/branding/favicon/delete")
async def admin_branding_favicon_delete(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    token = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/admin/branding", status_code=302)
    clear_branding_asset(
        db,
        kind="favicon",
        actor=_actor(user),
        ip_address=client_ip_from_request(request),
        settings=settings,
    )
    flash_redirect(response, "Favicon supprimé.", "success", token)
    return response
