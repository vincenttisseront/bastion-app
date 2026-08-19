"""Admin HTML routes for ModSecurity / CRS Phase B pilotage."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.bastion.nginx_waf_export import ANOMALY_MAX, ANOMALY_MIN, VALID_MODES
from app.bastion.nginx_waf_reality import build_waf_ui_context
from app.database import get_db
from app.request_client_ip import client_ip_from_request
from app.security.waf import service as waf_service
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context, flash_redirect
from app.web.templates import render
from app.web.user_context import require_admin

router = APIRouter(tags=["admin-waf"], dependencies=[Depends(require_admin)])


def _ctx(request: Request, settings: Settings, **extra: Any) -> dict[str, Any]:
    return base_template_context(request, settings, APP_VERSION, **extra)


def _actor(user) -> str:
    return (getattr(user, "email", None) or getattr(user, "username", None) or "admin")


def _flash_secret(settings: Settings) -> str:
    return settings.vault_portal_internal_token or "dev"


def _waf_page_context(
    db: Session,
    settings: Settings,
    *,
    page: str,
) -> dict[str, Any]:
    profile = waf_service.ensure_active_profile(db)
    exclusions = waf_service.list_exclusions(db)
    return {
        "profile": profile,
        "profiles": waf_service.list_profiles(db),
        "exclusions": exclusions,
        "anomaly_min": ANOMALY_MIN,
        "anomaly_max": ANOMALY_MAX,
        "valid_modes": sorted(VALID_MODES),
        **build_waf_ui_context(db, settings, profile, exclusions, page=page),
    }


@router.get("/admin/security/protection")
def admin_protection_redirect():
    """Lot 5 route — permanent redirect to unified WAF page (lot 6)."""
    return RedirectResponse(url="/admin/security/waf#bilan", status_code=301)


@router.get("/admin/security/waf/status")
def admin_waf_status_redirect():
    """Legacy anchor /admin/security/waf#status → bilan."""
    return RedirectResponse(url="/admin/security/waf#bilan", status_code=301)


@router.get("/admin/security/waf")
def admin_waf_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    return render(
        "admin/waf.html",
        **_ctx(request, settings, **_waf_page_context(db, settings, page="unified")),
    )


@router.post("/admin/security/waf/profile")
def admin_waf_profile_post(
    request: Request,
    mode: str = Form(...),
    anomaly_threshold: int = Form(...),
    profile_preset: str = Form("Custom"),
    ip_deny_min_occurrences: int = Form(3),
    portal_login_rate: int = Form(3),
    portal_api_rate: int = Form(30),
    portal_login_burst: int = Form(5),
    portal_api_burst: int = Form(60),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    response = RedirectResponse(url="/admin/security/waf#profile", status_code=302)
    try:
        waf_service.update_active_profile(
            db,
            mode=mode.strip(),
            anomaly_threshold=int(anomaly_threshold),
            profile_name=profile_preset.strip() or None,
            ip_deny_min_occurrences=int(ip_deny_min_occurrences),
            portal_login_rate=int(portal_login_rate),
            portal_api_rate=int(portal_api_rate),
            portal_login_burst=int(portal_login_burst),
            portal_api_burst=int(portal_api_burst),
            actor=_actor(user),
            ip_address=client_ip_from_request(request) or None,
        )
        flash_redirect(
            response,
            "Profil WAF enregistré (pas encore appliqué à nginx).",
            "success",
            _flash_secret(settings),
        )
    except ValueError as exc:
        flash_redirect(response, str(exc), "error", _flash_secret(settings))
    return response


@router.post("/admin/security/waf/exclusions/add")
def admin_waf_exclusion_add(
    request: Request,
    reason: str = Form(...),
    crs_rule_id: int = Form(...),
    uri_pattern: str = Form(""),
    host: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    response = RedirectResponse(url="/admin/security/waf#exclusions", status_code=302)
    try:
        waf_service.add_exclusion(
            db,
            reason=reason,
            crs_rule_id=int(crs_rule_id),
            uri_pattern=uri_pattern,
            host=host,
            actor=_actor(user),
            ip_address=client_ip_from_request(request) or None,
        )
        flash_redirect(response, "Exclusion ajoutée.", "success", _flash_secret(settings))
    except ValueError as exc:
        flash_redirect(response, str(exc), "error", _flash_secret(settings))
    return response


@router.post("/admin/security/waf/exclusions/{exclusion_id}/disable")
def admin_waf_exclusion_disable(
    request: Request,
    exclusion_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    response = RedirectResponse(url="/admin/security/waf#exclusions", status_code=302)
    try:
        waf_service.disable_exclusion(
            db,
            exclusion_id,
            actor=_actor(user),
            ip_address=client_ip_from_request(request) or None,
        )
        flash_redirect(
            response,
            "Exclusion désactivée (historique conservé).",
            "success",
            _flash_secret(settings),
        )
    except ValueError as exc:
        flash_redirect(response, str(exc), "error", _flash_secret(settings))
    return response


@router.post("/admin/security/waf/apply")
def admin_waf_apply(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    response = RedirectResponse(url="/admin/security/waf", status_code=302)
    result = waf_service.apply_waf(
        db,
        settings,
        actor=_actor(user),
        ip_address=client_ip_from_request(request) or None,
    )
    if result.get("ok"):
        detail = result.get("validate_detail") or ""
        flash_redirect(
            response,
            f"Exports WAF générés. {detail}",
            "success",
            _flash_secret(settings),
        )
    else:
        err = result.get("error") or "échec apply"
        flash_redirect(
            response,
            f"Apply annulé (nginx -t / validation). Config précédente restaurée. {err}",
            "error",
            _flash_secret(settings),
        )
    return response
