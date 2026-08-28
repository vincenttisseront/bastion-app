"""Admin HTML routes for ModSecurity / CRS Phase B pilotage."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from app.bastion.nginx_waf_export import ANOMALY_MAX, ANOMALY_MIN, VALID_MODES
from app.bastion.nginx_waf_reality import build_waf_ui_context
from app.bastion.waf_readability import format_waf_diagnostic_export_json
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
        "waf_profiles_map": waf_service.profiles_for_ui(db),
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


@router.get("/admin/security/waf/diagnostic.json")
def admin_waf_diagnostic_json(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Download expected vs actual WAF config for support / debug."""
    ctx = _waf_page_context(db, settings, page="unified")
    payload = ctx["diagnostic_export"]
    body = format_waf_diagnostic_export_json(payload)
    stamp = (payload.get("generated_at") or "now")[:19].replace(":", "").replace("-", "")
    return Response(
        content=body,
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="bastion-waf-diagnostic-{stamp}.json"',
            "Cache-Control": "no-store",
        },
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


@router.post("/admin/security/waf/actions/ban-ip")
def admin_waf_ban_ip(
    request: Request,
    ip: str = Form(...),
    ban_mode: str = Form("temporary"),
    ban_minutes: int = Form(1440),
    confirm_permanent: str | None = Form(None),
    reason: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Security action: ban an attacker IP seen in WAF audit (→ SecurityBan / nginx deny)."""
    from app.security.banning.service import apply_manual_ban

    response = RedirectResponse(url="/admin/security/waf#bilan", status_code=302)
    target = (ip or "").strip()
    if not target or target == "—" or any(c.isspace() for c in target):
        flash_redirect(response, "IP invalide.", "error", _flash_secret(settings))
        return response

    permanent = ban_mode == "permanent"
    ban = apply_manual_ban(
        db,
        target_type="ip",
        target=target,
        reason=(reason or "").strip() or f"WAF — ban depuis bilan ({target})",
        permanent=permanent,
        ban_minutes=max(1, int(ban_minutes)),
        confirm_permanent=confirm_permanent == "on",
        actor=_actor(user),
        ip_address=client_ip_from_request(request) or None,
    )
    if ban is None and permanent and confirm_permanent != "on":
        flash_redirect(
            response,
            "Ban permanent refusé : cochez la confirmation.",
            "error",
            _flash_secret(settings),
        )
    elif ban is None:
        flash_redirect(
            response,
            "Ban non appliqué (allowlist ou déjà banni).",
            "error",
            _flash_secret(settings),
        )
    elif permanent:
        flash_redirect(
            response,
            f"IP {target} bannie (permanent). Cliquez Appliquer pour pousser le deny nginx.",
            "success",
            _flash_secret(settings),
        )
    else:
        flash_redirect(
            response,
            f"IP {target} bannie ({ban_minutes} min). "
            "Deny nginx seulement si permanent ou seuil d’occurrences atteint — Appliquer si besoin.",
            "success",
            _flash_secret(settings),
        )
    return response


@router.post("/admin/security/waf/actions/exclude-rule")
def admin_waf_exclude_from_event(
    request: Request,
    crs_rule_id: int = Form(...),
    host: str = Form(""),
    uri_pattern: str = Form(""),
    reason: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Security tuning: create a CRS exclusion from a detected event (false positive path)."""
    response = RedirectResponse(url="/admin/security/waf#bilan", status_code=302)
    try:
        waf_service.add_exclusion(
            db,
            reason=(reason or "").strip()
            or f"Exclusion depuis détection WAF (règle {crs_rule_id})",
            crs_rule_id=int(crs_rule_id),
            uri_pattern=uri_pattern,
            host=host,
            actor=_actor(user),
            ip_address=client_ip_from_request(request) or None,
        )
        flash_redirect(
            response,
            f"Exclusion règle {crs_rule_id} enregistrée — Appliquer pour nginx.",
            "success",
            _flash_secret(settings),
        )
    except ValueError as exc:
        flash_redirect(response, str(exc), "error", _flash_secret(settings))
    return response


@router.post("/admin/security/waf/actions/quick-toggle")
def admin_waf_quick_toggle(
    request: Request,
    toggle: str = Form(...),
    enabled: str = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Toggle CRS or anti-bruteforce from Sentinel dashboard."""
    from app.bastion.nginx_waf_export import MODE_OFF, MODE_ON
    from app.security.banning.service import update_policy_misc

    response = RedirectResponse(url="/admin/security/waf#bilan", status_code=302)
    actor = _actor(user)
    ip = client_ip_from_request(request) or None
    turn_on = enabled == "on"
    try:
        if toggle == "bruteforce":
            update_policy_misc(
                db,
                enabled=turn_on,
                actor=actor,
                ip_address=ip,
            )
            flash_redirect(
                response,
                f"Anti-bruteforce {'activé' if turn_on else 'désactivé'}.",
                "success",
                _flash_secret(settings),
            )
        elif toggle == "crs":
            profile = waf_service.ensure_active_profile(db)
            new_mode = MODE_ON if turn_on else MODE_OFF
            waf_service.update_active_profile(
                db,
                mode=new_mode,
                anomaly_threshold=int(profile.anomaly_threshold or 5),
                actor=actor,
                ip_address=ip,
            )
            flash_redirect(
                response,
                f"Inspection CRS → {new_mode}. Appliquer pour nginx.",
                "success",
                _flash_secret(settings),
            )
        elif toggle == "geoloc":
            if not settings.ip_geoloc_enabled:
                flash_redirect(
                    response,
                    "Géolocalisation verrouillée par configuration serveur.",
                    "error",
                    _flash_secret(settings),
                )
            else:
                waf_service.set_ip_geoloc_enabled(
                    db,
                    enabled=turn_on,
                    actor=actor,
                    ip_address=ip,
                )
                flash_redirect(
                    response,
                    f"Géolocalisation IP {'activée' if turn_on else 'désactivée'}.",
                    "success",
                    _flash_secret(settings),
                )
        else:
            flash_redirect(response, "Contrôle inconnu.", "error", _flash_secret(settings))
    except ValueError as exc:
        flash_redirect(response, str(exc), "error", _flash_secret(settings))
    return response


@router.post("/admin/security/waf/actions/lift-ban/{ban_id}")
def admin_waf_lift_ban(
    ban_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.security.banning.service import lift_ban

    lift_ban(
        db,
        ban_id,
        actor=_actor(user),
        ip_address=client_ip_from_request(request) or None,
    )
    response = RedirectResponse(url="/admin/security/waf#bilan", status_code=302)
    flash_redirect(response, "IP débloquée.", "success", _flash_secret(settings))
    return response


@router.post("/admin/security/waf/actions/reactivate")
def admin_waf_reactivate(
    request: Request,
    confirm_reactivate: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Réactive ModSecurity portal (DetectionOnly) avec smoke + rollback auto."""
    from app.bastion.waf_reactivation import reactivate_engine
    from app.audit import log_action

    result = reactivate_engine(
        db,
        settings,
        actor=_actor(user),
        confirm=confirm_reactivate == "on",
    )
    # Succès → bilan (onglet Réactivation disparaît) ; échec → rester sur l'onglet.
    anchor = "#bilan" if result.get("ok") else "#reactivation"
    response = RedirectResponse(url=f"/admin/security/waf{anchor}", status_code=302)
    log_action(
        db,
        actor=_actor(user),
        action="security.waf.reactivate",
        target="portal",
        details={
            "ok": result.get("ok"),
            "rolled_back": result.get("rolled_back"),
            "error": result.get("error"),
            "mode": result.get("mode"),
            "sync_detail": result.get("sync_detail"),
            "failed_summary": result.get("failed_summary"),
            "failed_probes": result.get("failed_probes") or [],
            "smoke_ok": (result.get("smoke") or {}).get("ok"),
        },
        ip_address=client_ip_from_request(request) or None,
    )
    db.commit()
    if result.get("ok"):
        flash_redirect(
            response,
            result.get("message") or "Moteur réactivé (DetectionOnly), smoke OK.",
            "success",
            _flash_secret(settings),
        )
    else:
        flash_redirect(
            response,
            result.get("error") or "Réactivation échouée.",
            "error",
            _flash_secret(settings),
        )
    return response


@router.post("/admin/security/waf/actions/reactivate-subdomain")
def admin_waf_reactivate_subdomain(
    request: Request,
    confirm_reactivate_subdomain: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Réactive ModSecurity subdomain (DetectionOnly) avec smoke + rollback auto."""
    from app.bastion.waf_reactivation import reactivate_subdomain_engine
    from app.audit import log_action

    result = reactivate_subdomain_engine(
        db,
        settings,
        actor=_actor(user),
        confirm=confirm_reactivate_subdomain == "on",
    )
    anchor = "#bilan" if result.get("ok") else "#reactivation"
    response = RedirectResponse(url=f"/admin/security/waf{anchor}", status_code=302)
    log_action(
        db,
        actor=_actor(user),
        action="security.waf.reactivate_subdomain",
        target="subdomain",
        details={
            "ok": result.get("ok"),
            "rolled_back": result.get("rolled_back"),
            "error": result.get("error"),
            "mode": result.get("mode"),
            "sync_detail": result.get("sync_detail"),
            "failed_summary": result.get("failed_summary"),
            "smoke_hosts": result.get("smoke_hosts") or [],
            "smoke_ok": (result.get("smoke") or {}).get("ok"),
        },
        ip_address=client_ip_from_request(request) or None,
    )
    db.commit()
    if result.get("ok"):
        flash_redirect(
            response,
            result.get("message") or "Subdomain réactivé (DetectionOnly), smoke OK.",
            "success",
            _flash_secret(settings),
        )
    else:
        flash_redirect(
            response,
            result.get("error") or "Réactivation subdomain échouée.",
            "error",
            _flash_secret(settings),
        )
    return response


@router.post("/admin/security/waf/actions/disarm")
def admin_waf_disarm(
    request: Request,
    confirm_disarm: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Coupe immédiatement ModSecurity portal (Off + connector off)."""
    from app.bastion.waf_reactivation import disarm_engine
    from app.audit import log_action
    from app.bastion.nginx_waf_export import MODE_OFF, ensure_active_profile

    response = RedirectResponse(url="/admin/security/waf#profile", status_code=302)
    if confirm_disarm != "on":
        flash_redirect(
            response,
            "Coupure refusée : confirmation requise.",
            "error",
            _flash_secret(settings),
        )
        return response

    profile = ensure_active_profile(db)
    profile.mode = MODE_OFF
    db.commit()
    result = disarm_engine(settings, actor=_actor(user), reason="ihm_disarm")
    log_action(
        db,
        actor=_actor(user),
        action="security.waf.disarm",
        target="portal",
        details={"ok": result.get("ok"), "sync": result.get("sync_detail")},
        ip_address=client_ip_from_request(request) or None,
    )
    db.commit()
    if result.get("ok"):
        flash_redirect(
            response,
            "Moteur portal coupé (Off). Smoke post-coupure OK.",
            "success",
            _flash_secret(settings),
        )
    else:
        flash_redirect(
            response,
            f"Coupure tentée mais sync/smoke imperfect: {result.get('sync_detail')}",
            "error",
            _flash_secret(settings),
        )
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
    elif result.get("rolled_back"):
        err = result.get("error") or "smoke en échec"
        flash_redirect(
            response,
            f"Apply annulé — rollback exports. {err}",
            "error",
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
