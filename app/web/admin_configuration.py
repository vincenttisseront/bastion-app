"""Admin → Général → Configuration (SMTP + SIEM)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.mail.smtp_service import smtp_configured
from app.portal_settings_service import ensure_portal_settings, update_smtp_settings
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context, flash_redirect
from app.web.templates import render
from app.web.user_context import require_admin

router = APIRouter(tags=["admin-configuration"], dependencies=[Depends(require_admin)])

_CONFIG_SIEM = "/admin/configuration#siem"


def _actor(user) -> str:
    return getattr(user, "email", None) or getattr(user, "username", None) or "admin"


def _form_bool(value: str | None) -> bool:
    return value is not None and str(value).strip().lower() not in ("", "0", "false", "off")


@router.get("/admin/configuration")
def admin_configuration_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.siem.settings_service import ensure_siem_settings, public_status as siem_public_status

    row = ensure_portal_settings(db, settings)
    siem_settings = ensure_siem_settings(db)
    ctx = base_template_context(
        request,
        settings,
        APP_VERSION,
        smtp={
            "enabled": bool(row.smtp_enabled),
            "host": row.smtp_host or "",
            "port": row.smtp_port or 587,
            "use_tls": bool(getattr(row, "smtp_use_tls", True)),
            "username": row.smtp_username or "",
            "password_configured": bool(row.smtp_password_encrypted),
            "from_email": row.smtp_from_email or "",
            "from_name": row.smtp_from_name or "",
            "ready": smtp_configured(row),
        },
        siem_settings=siem_settings,
        siem_status=siem_public_status(db),
    )
    return render("admin/configuration.html", **ctx)


@router.post("/admin/configuration")
async def admin_configuration_save(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    smtp_enabled: str | None = Form(None),
    smtp_host: str = Form(""),
    smtp_port: int = Form(587),
    smtp_use_tls: str | None = Form(None),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from_email: str = Form(""),
    smtp_from_name: str = Form(""),
):
    token = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/admin/configuration#smtp", status_code=302)
    try:
        update_smtp_settings(
            db,
            settings,
            actor=_actor(user),
            ip_address=client_ip_from_request(request),
            smtp_enabled=_form_bool(smtp_enabled),
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_use_tls=_form_bool(smtp_use_tls),
            smtp_username=smtp_username,
            smtp_password=smtp_password,
            smtp_from_email=smtp_from_email,
            smtp_from_name=smtp_from_name,
        )
        flash_redirect(response, "Configuration SMTP enregistrée.", "success", token)
    except ValueError as exc:
        flash_redirect(response, str(exc), "error", token)
    return response


@router.post("/admin/configuration/siem")
def admin_configuration_siem(
    request: Request,
    enabled: str | None = Form(None),
    protocol: str = Form("webhook_https"),
    syslog_host: str = Form(""),
    syslog_port: int = Form(6514),
    syslog_tls_verify: str | None = Form(None),
    webhook_url: str = Form(""),
    webhook_auth_type: str = Form("none"),
    webhook_auth_secret: str = Form(""),
    clear_webhook_secret: str | None = Form(None),
    filter_mode: str = Form("denylist"),
    filter_actions: str = Form(""),
    retry_max_queue_size: int = Form(5000),
    retry_max_age_minutes: int = Form(1440),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.siem.settings_service import update_siem_settings

    token = settings.vault_portal_internal_token or "dev"
    actions = [
        a.strip()
        for a in (filter_actions or "").replace(";", ",").split(",")
        if a.strip()
    ]
    try:
        update_siem_settings(
            db,
            settings,
            enabled=enabled == "on",
            protocol=protocol,
            syslog_host=syslog_host,
            syslog_port=syslog_port,
            syslog_tls_verify=syslog_tls_verify == "on",
            webhook_url=webhook_url,
            webhook_auth_type=webhook_auth_type,
            webhook_auth_secret=webhook_auth_secret or None,
            clear_webhook_secret=clear_webhook_secret == "on",
            filter_mode=filter_mode,
            filter_actions=actions,
            retry_max_queue_size=retry_max_queue_size,
            retry_max_age_minutes=retry_max_age_minutes,
            actor=_actor(user),
            ip_address=client_ip_from_request(request),
        )
    except ValueError as exc:
        response = RedirectResponse(url=_CONFIG_SIEM, status_code=302)
        flash_redirect(response, str(exc), "error", token)
        return response
    response = RedirectResponse(url=_CONFIG_SIEM, status_code=302)
    flash_redirect(response, "Paramètres SIEM enregistrés.", "success", token)
    return response


@router.post("/admin/configuration/siem/test")
def admin_configuration_siem_test(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.siem.outbox import run_connectivity_test

    ok, message = run_connectivity_test(
        db,
        settings,
        actor=_actor(user),
    )
    response = RedirectResponse(url=_CONFIG_SIEM, status_code=302)
    flash_redirect(
        response,
        message,
        "success" if ok else "error",
        settings.vault_portal_internal_token or "dev",
    )
    return response
