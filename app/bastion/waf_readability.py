"""WAF admin page readability — verdict, protection layers, efficiency (lot 4)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.bastion.modsec_audit_aggregator import read_audit_summary
from app.bastion.nginx_waf_export import MODE_DETECTION, MODE_OFF, MODE_ON, list_promoted_deny_ips
from app.models import AuditLog, SecurityBanRule, WafProfile
from app.security.banning.service import list_active_bans, list_ban_rules, get_or_create_policy
from app.sso_settings import Settings

CRS_INACTIVE_CAUSE = "Moteur ModSecurity arrêté depuis l'urgence du 2026-08-06."
SNAPSHOT_UNAVAILABLE_RESOLUTION = (
    "Le snapshot nginx (nginx-waf-snapshot.json) est absent ou illisible — "
    "rebuild bastion-nginx et vérifiez le volume nginx-logs."
)
AGGREGATOR_UNAVAILABLE_RESOLUTION = (
    "L'agrégateur n'a pas encore produit de résumé — vérifiez que bastion-app "
    "tourne avec le job APScheduler (leader health probe, toutes les 5 min)."
)


def _count_unknown_host_refusals_24h(db: Session) -> int:
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    try:
        return (
            db.query(func.count(AuditLog.id))
            .filter(
                AuditLog.action == "access_denied_unknown_host",
                AuditLog.created_at >= since,
            )
            .scalar()
            or 0
        )
    except Exception:
        return 0


def _verdict_action(
    href: str | None,
    *,
    label: str | None,
    apply: bool = False,
    page: str = "dashboard",
) -> dict[str, Any]:
    """Map verdict actions to dashboard links or in-page anchors."""
    if not label:
        return {"action_label": None, "action_href": None, "action_apply": False}
    if page == "dashboard":
        if apply or not href:
            return {
                "action_label": label,
                "action_href": "/admin/security/waf",
                "action_apply": False,
            }
        if href.startswith("#"):
            return {
                "action_label": label,
                "action_href": f"/admin/security/waf{href}",
                "action_apply": False,
            }
    return {"action_label": label, "action_href": href, "action_apply": apply}


def build_protection_verdict(
    profile: WafProfile,
    active: dict[str, Any],
    *,
    export_pending: bool,
    page: str = "dashboard",
) -> dict[str, Any]:
    """Single admin-facing verdict from nginx reality + DB intent."""
    desired = profile.mode
    real = active.get("aggregate_mode") if active.get("verifiable") else None

    if not active.get("verifiable"):
        return {
            "level": "unknown",
            "css": "alert-warn",
            "title": "État de protection : non vérifiable",
            "message": (
                "Impossible de lire l'état réel du moteur nginx — la source de vérité "
                "(snapshot) n'est pas disponible. Les indicateurs CRS ci-dessous restent "
                "inconnus tant que le snapshot n'est pas produit."
            ),
            "resolution": SNAPSHOT_UNAVAILABLE_RESOLUTION,
            **_verdict_action(
                "#technical-details",
                label="Voir le diagnostic technique",
                page=page,
            ),
        }

    if real == MODE_OFF:
        return {
            "level": "inactive",
            "css": "alert-err",
            "title": "Inspection du contenu : INACTIVE",
            "message": (
                "Aucune protection contre les injections (SQLi, XSS, RCE, LFI). "
                f"{CRS_INACTIVE_CAUSE}"
            ),
            **_verdict_action(
                "#technical-details",
                label="Voir la procédure de réactivation",
                page=page,
            ),
            "action_hint": "docs/runbook-reactivation-crs-modsecurity.md",
        }

    if real == MODE_DETECTION:
        return {
            "level": "observe",
            "css": "alert-warn",
            "title": "Inspection ACTIVE, mode observation",
            "message": (
                "Les requêtes sont analysées par le CRS, mais aucune n'est bloquée "
                "(DetectionOnly)."
            ),
            **_verdict_action("#profile", label="Ajuster le profil", page=page),
        }

    if desired != real or export_pending:
        return {
            "level": "mismatch",
            "css": "alert-err",
            "title": "Configuration non appliquée",
            "message": (
                "Ce que vous avez enregistré n'est pas ce qui tourne actuellement sur nginx."
            ),
            **_verdict_action(
                "#profile" if not export_pending else None,
                label=(
                    "Appliquer la configuration"
                    if export_pending
                    else "Vérifier le profil"
                ),
                apply=export_pending,
                page=page,
            ),
        }

    if real == MODE_ON and desired == MODE_ON:
        return {
            "level": "active",
            "css": "alert-ok",
            "title": "Inspection ACTIVE",
            "message": "Requêtes malveillantes détectées par le CRS sont bloquées.",
            "action_label": None,
            "action_href": None,
            "action_apply": False,
        }

    return {
        "level": "info",
        "css": "alert-warn",
        "title": f"État nginx : {real or '—'}",
        "message": "Vérifiez l'alignement entre le profil enregistré et l'état réel.",
        **_verdict_action(
            "#technical-details",
            label="Voir les détails techniques",
            page=page,
        ),
    }


def build_protection_status_line(verdict: dict[str, Any]) -> dict[str, Any]:
    """One-line protection reminder for the configuration page."""
    return {
        "text": verdict.get("title") or "État de protection inconnu",
        "css": verdict.get("css") or "alert-warn",
        "href": "/admin/security/protection",
    }


def build_protection_layers(
    db: Session,
    profile: WafProfile,
    active: dict[str, Any],
    headers_panel: dict[str, Any],
) -> list[dict[str, Any]]:
    """Synthèse de toutes les couches de protection."""
    policy = get_or_create_policy(db)
    ban_rules = list_ban_rules(db)
    active_rules = [r for r in ban_rules if r.enabled]
    active_bans = list_active_bans(db)
    promoted_ips = list_promoted_deny_ips(
        db, min_occurrences=int(profile.ip_deny_min_occurrences or 3)
    )
    unknown_refusals = _count_unknown_host_refusals_24h(db)

    crs_mode = active.get("aggregate_mode") if active.get("verifiable") else None
    if crs_mode == MODE_ON:
        crs_state, crs_css = "active", "badge-ok"
        crs_detail = "Blocage actif"
    elif crs_mode == MODE_DETECTION:
        crs_state, crs_css = "observation", "badge-warn"
        crs_detail = "Observation seule"
    elif crs_mode == MODE_OFF:
        crs_state, crs_css = "inactive", "badge-err"
        crs_detail = "Moteur arrêté"
    else:
        crs_state, crs_css = "inconnu", "badge-muted"
        crs_detail = "Non vérifiable"

    headers_verifiable = bool(active.get("verifiable") and headers_panel.get("present"))
    if headers_verifiable:
        header_count = len(headers_panel.get("headers") or [])
        if header_count:
            headers_state, headers_css = "actif", "badge-ok"
            headers_detail = f"{header_count} en-tête(s) actif(s) sur :443"
        else:
            headers_state, headers_css = "aucun détecté", "badge-muted"
            headers_detail = "0 en-tête(s) actif(s) sur :443 (mesuré)"
    else:
        headers_state, headers_css = "non vérifiable", "badge-muted"
        headers_detail = SNAPSHOT_UNAVAILABLE_RESOLUTION

    anti_bruteforce_css = "badge-ok" if policy.enabled else "badge-err"
    anti_bruteforce_state = "actif" if policy.enabled else "désactivé (global)"

    return [
        {
            "name": "Anti-bruteforce",
            "state": anti_bruteforce_state,
            "css": anti_bruteforce_css,
            "detail": f"{len(active_rules)} règles actives · {len(active_bans)} bans en cours",
            "alert": not policy.enabled,
        },
        {
            "name": "Rate limit nginx",
            "state": "actif",
            "css": "badge-ok",
            "detail": (
                f"{profile.portal_login_rate} r/s login · "
                f"{profile.portal_api_rate} r/s API"
            ),
            "alert": False,
        },
        {
            "name": "Blocage IP (deny)",
            "state": "actif" if promoted_ips else "aucune IP",
            "css": "badge-ok" if promoted_ips else "badge-muted",
            "detail": f"{len(promoted_ips)} IP promue(s) vers nginx",
            "alert": False,
        },
        {
            "name": "Filtrage d'hôtes",
            "state": "actif",
            "css": "badge-ok",
            "detail": f"{unknown_refusals} refus / 24 h (hôtes non enregistrés)",
            "alert": False,
        },
        {
            "name": "En-têtes de sécurité",
            "state": headers_state,
            "css": headers_css,
            "detail": headers_detail,
            "alert": not headers_verifiable,
        },
        {
            "name": "Inspection CRS",
            "state": crs_state,
            "css": crs_css,
            "detail": crs_detail,
            "alert": crs_mode in (MODE_OFF, None),
        },
    ]


def build_efficiency_panel(
    settings: Settings,
    active: dict[str, Any],
    *,
    window: str = "24h",
) -> dict[str, Any]:
    """Read pre-aggregated counters — never parses raw log."""
    summary = read_audit_summary(settings)
    if not summary.get("present"):
        return {
            "present": False,
            "status": "unavailable",
            "message": (
                summary.get("status_message")
                or "Données d'efficacité indisponibles — mesure jamais effectuée."
            ),
            "resolution": AGGREGATOR_UNAVAILABLE_RESOLUTION,
        }

    if not summary.get("log_available"):
        return {
            "present": False,
            "status": "unavailable",
            "message": "Journal d'audit ModSecurity absent — données indisponibles.",
            "resolution": (
                "Le fichier modsec_audit.log est absent du volume nginx-logs — "
                "normal tant que le moteur CRS est arrêté."
            ),
        }

    windows = summary.get("windows") or {}
    data = windows.get(window) or windows.get("24h") or {}
    crs_mode = active.get("aggregate_mode") if active.get("verifiable") else None
    inspected = int(data.get("inspected") or 0)

    zero_explanation = None
    status = "ok"
    if inspected == 0:
        status = "measured_zero"
        if crs_mode == MODE_OFF:
            zero_explanation = (
                "0 requête inspectée : le moteur est arrêté. "
                "Ces compteurs sont cohérents, ce n'est pas une panne de la supervision."
            )
        elif crs_mode == MODE_DETECTION:
            zero_explanation = (
                "Mesure effectuée — aucune inspection enregistrée sur la période. "
                "Vérifiez que l'audit ModSecurity est activé."
            )
        else:
            zero_explanation = (
                "Mesure effectuée — aucune activité CRS enregistrée sur la période."
            )

    return {
        "present": True,
        "status": status,
        "window": window,
        "generated_at": summary.get("generated_at"),
        "inspected": inspected,
        "detections": int(data.get("detections") or 0),
        "blocks": int(data.get("blocks") or 0),
        "block_rate_pct": data.get("block_rate_pct") or 0,
        "top_rules": data.get("top_rules") or [],
        "top_hosts": data.get("top_hosts") or [],
        "zero_explanation": zero_explanation,
        "windows_available": list(windows.keys()),
    }


def build_waf_readability_context(
    db: Session,
    settings: Settings,
    profile: WafProfile,
    active: dict[str, Any],
    headers_panel: dict[str, Any],
    *,
    export_pending: bool,
    page: str = "dashboard",
) -> dict[str, Any]:
    verdict = build_protection_verdict(
        profile, active, export_pending=export_pending, page=page
    )
    layers = build_protection_layers(db, profile, active, headers_panel)
    efficiency_24h = build_efficiency_panel(settings, active, window="24h")
    efficiency_7d = build_efficiency_panel(settings, active, window="7d")
    return {
        "verdict": verdict,
        "protection_status_line": build_protection_status_line(verdict),
        "protection_layers": layers,
        "efficiency": efficiency_24h,
        "efficiency_7d": efficiency_7d,
    }
