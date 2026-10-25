"""Admin HTML routes for ModSecurity / CRS."""

from __future__ import annotations

import logging
from typing import Any

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.audit import admin_actor
from app.bastion.nginx_waf_export import (
    ANOMALY_MAX,
    ANOMALY_MIN,
    PARANOIA_MAX,
    PARANOIA_MIN,
    VALID_MODES,
)
from app.bastion.nginx_waf_reality import build_waf_ui_context
from app.bastion.waf_readability import format_waf_diagnostic_export_json
from app.database import get_db
from app.request_client_ip import client_ip_from_request
from app.security.waf import service as waf_service
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.csrf import portal_signing_secret
from app.web.flash import base_template_context, flash_redirect
from app.web.templates import render
from app.web.user_context import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-waf"], dependencies=[Depends(require_admin)])

_WAF_URL_BILAN = "/admin/security/waf#bilan"
_WAF_URL_EXCLUSIONS = "/admin/security/waf#exclusions"
_WAF_URL_NETWORK = "/admin/security/waf#network-control"
_WAF_ANCHOR_BILAN = "#bilan"
_WAF_ANCHOR_REACTIVATION = "#reactivation"


def _ctx(request: Request, settings: Settings, **extra: Any) -> dict[str, Any]:
    return base_template_context(request, settings, APP_VERSION, **extra)


def _flash_secret(settings: Settings) -> str:
    return portal_signing_secret(settings)


def _waf_page_context(
    db: Session,
    settings: Settings,
    *,
    page: str,
) -> dict[str, Any]:
    from app.bastion.modsec_audit_aggregator import CRS_RULE_LABELS, read_audit_summary
    from app.bastion.nginx_known_hosts_export import collect_known_hostnames

    profile = waf_service.ensure_active_profile(db)
    exclusions = waf_service.list_exclusions(db)
    hosts = [
        h
        for h in collect_known_hostnames(db, settings)
        if h not in ("127.0.0.1", "localhost")
    ]
    suggestions: dict[str, str] = dict(CRS_RULE_LABELS)
    try:
        summary = read_audit_summary(settings) or {}
        for item in summary.get("top_rules") or []:
            if isinstance(item, dict):
                sid = str(item.get("rule_id") or item.get("id") or "").strip()
                label = str(item.get("label") or item.get("message") or "").strip()
            else:
                sid = str(item).strip()
                label = ""
            if sid.isdigit() and sid not in suggestions:
                suggestions[sid] = label[:60] if label else f"Règle CRS {sid}"
        for ev in summary.get("recent_events") or []:
            if not isinstance(ev, dict):
                continue
            sid = str(ev.get("rule_id") or "").strip()
            if sid.isdigit() and sid not in suggestions:
                msg = str(ev.get("message") or "").strip()
                suggestions[sid] = (msg[:60] if msg else f"Règle CRS {sid}")
    except Exception:  # noqa: BLE001 — suggestions are optional, the page must render
        logger.warning("WAF rule suggestions unavailable", exc_info=True)
    rule_suggestions = [
        {"id": rid, "label": f"{rid} — {label}"}
        for rid, label in sorted(suggestions.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0)
    ]
    from app.security.banning.service import list_allowlist

    allowlist = list_allowlist(db)
    return {
        "profile": profile,
        "profiles": waf_service.list_profiles(db),
        "waf_profiles_map": waf_service.profiles_for_ui(db),
        "exclusions": exclusions,
        "allowlist": allowlist,
        "exclusion_hosts": hosts,
        "crs_rule_suggestions": rule_suggestions,
        "anomaly_min": ANOMALY_MIN,
        "anomaly_max": ANOMALY_MAX,
        "paranoia_min": PARANOIA_MIN,
        "paranoia_max": PARANOIA_MAX,
        "valid_modes": sorted(VALID_MODES),
        **build_waf_ui_context(db, settings, profile, exclusions, page=page),
    }


@router.get("/admin/security/protection")
def admin_protection_redirect():
    """Redirect legacy URL to the unified WAF page."""
    return RedirectResponse(url=_WAF_URL_BILAN, status_code=301)


@router.get("/admin/security/waf/status")
def admin_waf_status_redirect():
    """Legacy anchor /admin/security/waf#status → bilan."""
    return RedirectResponse(url=_WAF_URL_BILAN, status_code=301)


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


@router.get("/admin/security/waf/drift.json")
def admin_waf_drift_json(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """UI target vs on-disk exports unified diffs (Détails techniques)."""
    from app.bastion.waf_config_drift import build_waf_config_drift

    payload = build_waf_config_drift(db, settings)
    return JSONResponse(payload, headers={"Cache-Control": "no-store"})


@router.post("/admin/security/waf/sandbox")
def admin_waf_sandbox(
    request: Request,
    method: str = Form("GET"),
    uri: str = Form("/"),
    body: str = Form(""),
    content_type: str = Form("application/x-www-form-urlencoded"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Internal ModSecurity sandbox probe (DetectionOnly) + audit correlation."""
    from app.audit import log_action
    from app.bastion.waf_sandbox import run_waf_sandbox

    _ = db  # auth + future rate limits
    try:
        result = run_waf_sandbox(
            settings,
            method=method,
            uri=uri,
            body=body,
            content_type=content_type,
        )
    except ValueError as exc:
        return JSONResponse(
            {"ok": False, "error": str(exc)},
            status_code=400,
            headers={"Cache-Control": "no-store"},
        )
    log_action(
        db,
        actor=admin_actor(user),
        action="security.waf.sandbox_probe",
        target=result.get("sandbox_id"),
        details={
            "method": result.get("method"),
            "uri": result.get("uri"),
            "verdict": result.get("verdict"),
            "blocked_intent": result.get("blocked_intent"),
            "rules": [r.get("id") for r in (result.get("matched_rules") or [])][:20],
        },
        ip_address=client_ip_from_request(request) or None,
    )
    return JSONResponse(
        {"ok": True, **result},
        headers={"Cache-Control": "no-store"},
    )


@router.get("/admin/security/waf/modsecurity.json")
def admin_waf_modsecurity_json(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Live ModSecurity panel payload for tab auto-refresh (engine + packs)."""
    from app.bastion.nginx_waf_reality import portal_engine_mode, read_nginx_waf_reality
    from app.bastion.waf_readability import build_reactivation_panel
    from app.bastion.waf_virtual_patches import build_modsecurity_page

    profile = waf_service.ensure_active_profile(db)
    active = read_nginx_waf_reality(settings=settings)
    if active.get("verifiable"):
        active = {**active, "portal_mode": portal_engine_mode(active)}
    reactivation = build_reactivation_panel(
        profile, active, settings, db, export_pending=False
    )
    modsecurity = build_modsecurity_page(
        db,
        settings,
        profile,
        active=active,
        reactivation=reactivation,
    )
    return JSONResponse(
        {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "modsecurity": modsecurity,
        },
        headers={"Cache-Control": "no-store"},
    )


@router.post("/admin/security/waf/profile")
def admin_waf_profile_post(
    request: Request,
    mode: str = Form(...),
    anomaly_threshold: int = Form(...),
    profile_preset: str = Form("Custom"),
    paranoia_level: int = Form(1),
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
            paranoia_level=int(paranoia_level),
            profile_name=profile_preset.strip() or None,
            ip_deny_min_occurrences=int(ip_deny_min_occurrences),
            portal_login_rate=int(portal_login_rate),
            portal_api_rate=int(portal_api_rate),
            portal_login_burst=int(portal_login_burst),
            portal_api_burst=int(portal_api_burst),
            actor=admin_actor(user),
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


@router.post("/admin/security/waf/modsecurity/packs/{pack_id}")
def admin_waf_modsecurity_pack_toggle(
    pack_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    mode: str | None = Form(None),
    enabled: str | None = Form(None),
):
    """Set virtual-patch pack mode off|detection|on (Appliquer to push nginx)."""
    response = RedirectResponse(url="/admin/security/waf#modsecurity", status_code=302)
    try:
        if mode is None or not str(mode).strip():
            # Legacy form: enabled=on|off
            if enabled is None:
                raise ValueError("mode pack requis (off|detection|on)")
            mode = "on" if enabled == "on" else "off"
        profile = waf_service.set_virtual_pack_mode(
            db,
            pack_id=pack_id.strip().lower(),
            mode=str(mode).strip().lower(),
            actor=admin_actor(user),
            ip_address=client_ip_from_request(request) or None,
        )
        labels = {
            "off": "désactivé",
            "detection": "en détection (DetectionOnly)",
            "on": "actif (blocage si moteur On)",
        }
        state = labels.get(str(mode).strip().lower(), str(mode))
        flash_redirect(
            response,
            f"Pack ModSecurity « {pack_id} » {state} (profil {profile.name}). "
            "Appliquer pour pousser vers nginx.",
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
    scope_kind: str = Form("rule"),
    target_name: str = Form(""),
    uri_match: str = Form("exact"),
    allow_global: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    response = RedirectResponse(url=_WAF_URL_EXCLUSIONS, status_code=302)
    try:
        waf_service.add_exclusion(
            db,
            reason=reason,
            crs_rule_id=int(crs_rule_id),
            uri_pattern=uri_pattern,
            host=host,
            scope_kind=scope_kind,
            target_name=target_name,
            uri_match=uri_match,
            allow_global=allow_global == "on",
            actor=admin_actor(user),
            ip_address=client_ip_from_request(request) or None,
        )
        flash_redirect(
            response,
            "Exclusion ajoutée — Appliquer pour pousser vers nginx.",
            "success",
            _flash_secret(settings),
        )
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
    response = RedirectResponse(url=_WAF_URL_EXCLUSIONS, status_code=302)
    try:
        waf_service.disable_exclusion(
            db,
            exclusion_id,
            actor=admin_actor(user),
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


@router.post("/admin/security/waf/exclusions/{exclusion_id}/delete")
def admin_waf_exclusion_delete(
    request: Request,
    exclusion_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    response = RedirectResponse(url=_WAF_URL_EXCLUSIONS, status_code=302)
    try:
        waf_service.delete_exclusion(
            db,
            exclusion_id,
            actor=admin_actor(user),
            ip_address=client_ip_from_request(request) or None,
        )
        flash_redirect(
            response,
            "Exclusion supprimée. Penser à Appliquer pour retirer la règle nginx.",
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

    response = RedirectResponse(url=_WAF_URL_BILAN, status_code=302)
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
        actor=admin_actor(user),
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
    scope_kind: str = Form("rule"),
    target_name: str = Form(""),
    uri_match: str = Form("exact"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Security tuning: create a CRS exclusion from a detected event (false positive path)."""
    response = RedirectResponse(url=_WAF_URL_EXCLUSIONS, status_code=302)
    try:
        waf_service.add_exclusion(
            db,
            reason=(reason or "").strip()
            or f"Exclusion depuis détection WAF (règle {crs_rule_id})",
            crs_rule_id=int(crs_rule_id),
            uri_pattern=uri_pattern,
            host=host,
            scope_kind=scope_kind or "rule",
            target_name=target_name,
            uri_match=uri_match or "exact",
            allow_global=False,
            actor=admin_actor(user),
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


def _quick_toggle_bruteforce(
    db: Session,
    *,
    turn_on: bool,
    actor: str,
    ip: str | None,
    response: RedirectResponse,
    settings: Settings,
) -> None:
    from app.security.banning.service import get_or_create_policy, update_policy_misc

    current = get_or_create_policy(db)
    update_policy_misc(
        db,
        enabled=turn_on,
        breakglass_allow_cidrs=current.breakglass_allow_cidrs or "",
        breakglass_deny_cidrs=current.breakglass_deny_cidrs or "",
        actor=actor,
        ip_address=ip,
    )
    flash_redirect(
        response,
        f"Anti-bruteforce {'activé' if turn_on else 'désactivé'}.",
        "success",
        _flash_secret(settings),
    )


def _quick_toggle_crs(
    db: Session,
    *,
    turn_on: bool,
    actor: str,
    ip: str | None,
    response: RedirectResponse,
    settings: Settings,
) -> None:
    from app.bastion.nginx_waf_export import MODE_OFF, MODE_ON

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


def _quick_toggle_geoloc(
    db: Session,
    *,
    turn_on: bool,
    actor: str,
    ip: str | None,
    response: RedirectResponse,
    settings: Settings,
) -> None:
    if not settings.ip_geoloc_enabled:
        flash_redirect(
            response,
            "Géolocalisation verrouillée par configuration serveur.",
            "error",
            _flash_secret(settings),
        )
        return
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
    response = RedirectResponse(url=_WAF_URL_BILAN, status_code=302)
    actor = admin_actor(user)
    ip = client_ip_from_request(request) or None
    turn_on = enabled == "on"
    handlers = {
        "bruteforce": _quick_toggle_bruteforce,
        "crs": _quick_toggle_crs,
        "geoloc": _quick_toggle_geoloc,
    }
    try:
        handler = handlers.get(toggle)
        if handler is None:
            flash_redirect(
                response, "Contrôle inconnu.", "error", _flash_secret(settings)
            )
        else:
            handler(
                db,
                turn_on=turn_on,
                actor=actor,
                ip=ip,
                response=response,
                settings=settings,
            )
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
        actor=admin_actor(user),
        ip_address=client_ip_from_request(request) or None,
    )
    response = RedirectResponse(url=_WAF_URL_NETWORK, status_code=302)
    flash_redirect(
        response,
        "Ban levé. Cliquez Appliquer si l’IP était dans waf-ip-deny.conf.",
        "success",
        _flash_secret(settings),
    )
    return response


@router.post("/admin/security/waf/allowlist/add")
def admin_waf_allowlist_add(
    request: Request,
    value: str = Form(...),
    comment: str = Form(...),
    entry_type: str = Form("ip"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.security.banning.service import add_allowlist_entry

    response = RedirectResponse(url=_WAF_URL_NETWORK, status_code=302)
    try:
        add_allowlist_entry(
            db,
            entry_type=(entry_type or "ip").strip().lower(),
            value=value,
            comment=(comment or "").strip(),
            actor=admin_actor(user),
            ip_address=client_ip_from_request(request) or None,
        )
        flash_redirect(
            response,
            "Entrée allowlist ajoutée. Cliquez Appliquer pour pousser waf-ip-allow.conf.",
            "success",
            _flash_secret(settings),
        )
    except ValueError as exc:
        flash_redirect(response, str(exc), "error", _flash_secret(settings))
    return response


@router.post("/admin/security/waf/allowlist/{entry_id}/remove")
def admin_waf_allowlist_remove(
    entry_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.security.banning.service import remove_allowlist_entry

    response = RedirectResponse(url=_WAF_URL_NETWORK, status_code=302)
    try:
        remove_allowlist_entry(
            db,
            entry_id,
            actor=admin_actor(user),
            ip_address=client_ip_from_request(request) or None,
        )
        flash_redirect(
            response,
            "Entrée allowlist retirée. Cliquez Appliquer pour synchroniser nginx.",
            "success",
            _flash_secret(settings),
        )
    except ValueError as exc:
        flash_redirect(response, str(exc), "error", _flash_secret(settings))
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
    from app.audit import log_action
    from app.bastion.waf_reactivation import reactivate_engine

    result = reactivate_engine(
        db,
        settings,
        actor=admin_actor(user),
        confirm=confirm_reactivate == "on",
    )
    # Succès → bilan (onglet Réactivation disparaît) ; échec → rester sur l'onglet.
    anchor = _WAF_ANCHOR_BILAN if result.get("ok") else _WAF_ANCHOR_REACTIVATION
    response = RedirectResponse(url=f"/admin/security/waf{anchor}", status_code=302)
    log_action(
        db,
        actor=admin_actor(user),
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
    from app.audit import log_action
    from app.bastion.waf_reactivation import reactivate_subdomain_engine

    result = reactivate_subdomain_engine(
        db,
        settings,
        actor=admin_actor(user),
        confirm=confirm_reactivate_subdomain == "on",
    )
    anchor = _WAF_ANCHOR_BILAN if result.get("ok") else _WAF_ANCHOR_REACTIVATION
    response = RedirectResponse(url=f"/admin/security/waf{anchor}", status_code=302)
    log_action(
        db,
        actor=admin_actor(user),
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


@router.post("/admin/security/waf/actions/promote-portal-on")
def admin_waf_promote_portal_on(
    request: Request,
    confirm_promote_portal_on: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.audit import log_action
    from app.bastion.waf_reactivation import promote_portal_engine_to_on

    result = promote_portal_engine_to_on(
        db,
        settings,
        actor=admin_actor(user),
        confirm=confirm_promote_portal_on == "on",
    )
    response = RedirectResponse(
        url=f"/admin/security/waf{_WAF_ANCHOR_REACTIVATION}", status_code=302
    )
    if result.get("ok"):
        log_action(
            db,
            actor=admin_actor(user),
            action="security.waf.promote_portal_on",
            resource_type="waf",
            resource_id="portal",
            detail={"mode": "on", "smoke_ok": True},
            ip_address=client_ip_from_request(request) or None,
        )
        flash_redirect(
            response,
            result.get("message") or "Portal promu en On.",
            "success",
            _flash_secret(settings),
        )
    else:
        flash_redirect(
            response,
            result.get("error") or "Promotion portal échouée.",
            "error",
            _flash_secret(settings),
        )
    return response


@router.post("/admin/security/waf/actions/promote-subdomain-on")
def admin_waf_promote_subdomain_on(
    request: Request,
    confirm_promote_subdomain_on: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Passe ModSecurity subdomain de DetectionOnly à On (smoke + rollback DetectionOnly)."""
    from app.audit import log_action
    from app.bastion.waf_reactivation import promote_subdomain_engine_to_on

    result = promote_subdomain_engine_to_on(
        db,
        settings,
        actor=admin_actor(user),
        confirm=confirm_promote_subdomain_on == "on",
    )
    anchor = _WAF_ANCHOR_BILAN if result.get("ok") else _WAF_ANCHOR_REACTIVATION
    response = RedirectResponse(url=f"/admin/security/waf{anchor}", status_code=302)
    log_action(
        db,
        actor=admin_actor(user),
        action="security.waf.promote_subdomain_on",
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
            result.get("message") or "Subdomain promu en On, smoke OK.",
            "success",
            _flash_secret(settings),
        )
    else:
        flash_redirect(
            response,
            result.get("error") or "Promotion subdomain On échouée.",
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
    from app.audit import log_action
    from app.bastion.nginx_waf_export import MODE_OFF, ensure_active_profile
    from app.bastion.waf_reactivation import disarm_engine

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
    result = disarm_engine(settings, actor=admin_actor(user), reason="ihm_disarm")
    log_action(
        db,
        actor=admin_actor(user),
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
        actor=admin_actor(user),
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
