"""WAF admin page readability — verdict, protection layers, efficiency."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.bastion.ip_geolocation import (
    collect_waf_dashboard_ips,
    country_flag,
    lookup_ip_origins,
    origin_from_geoloc,
    resolve_ip_geoloc_enabled,
)
from app.bastion.modsec_audit_aggregator import (
    RULE_FAMILY_LABELS,
    _rule_family,
    read_aggregator_state,
    read_audit_summary,
    resolve_audit_summary_path,
    resolve_aggregator_state_path,
    resolve_modsec_audit_log_path,
)
from app.bastion.nginx_waf_export import MODE_DETECTION, MODE_OFF, MODE_ON, list_promoted_deny_ips
from app.bastion.nginx_waf_reality import portal_engine_mode, resolve_nginx_waf_snapshot_path
from app.bastion.waf_charts import (
    render_attack_heatmap,
    render_dual_area_chart,
    render_family_breakdown,
    render_health_gauge,
    render_horizontal_bars,
    render_owasp_bars,
    render_series_chart,
    _empty_panel,
)
from app.models import App, AuditLog, PendingHost, SecurityBanRule, WafProfile
from app.security.banning.service import list_active_bans, list_ban_rules, get_or_create_policy
from app.sso_settings import Settings

CRS_INACTIVE_CAUSE = "Moteur ModSecurity désarmé (Off)."
CRS_INACTIVE_RESOLUTION = (
    "Utilisez « Réactiver » : DetectionOnly, sync nginx, contrôles HTTP. "
    "Rollback automatique vers Off si une sonde échoue."
)
UNKNOWN_HOST_FEED_RULE_LABEL = "Host HTTP non enregistré"
UNKNOWN_HOST_FEED_RULE_TITLE = (
    "Requête refusée : l'en-tête Host ne correspond à aucun domaine portail "
    "connu (scan IP direct, bot, apex non configuré)."
)
BAN_RULE_TYPE_LABELS: dict[str, str] = {
    "unknown_host_hammering": "Rafale host non enregistré",
    "hammering": "Rafale requêtes",
    "hammering_login": "Rafale login",
    "failed_login": "Échecs login",
    "successful_login": "Connexions suspectes",
    "hack_username": "Usernames invalides",
    "concurrent_connections": "Connexions simultanées",
    "rate_limit": "Rate limit",
    "rate_limit_login": "Rate limit login",
    "manual": "Manuel",
}
FEED_SOURCE_META: dict[str, dict[str, str]] = {
    "crs": {
        "kind": "modsecurity",
        "label": "CRS",
        "title": "Interception ModSecurity / OWASP CRS",
    },
    "unknown_host": {
        "kind": "host_filter",
        "label": "Filtrage",
        "title": "Refus nginx — en-tête Host absent du portail (hors ModSecurity)",
    },
}
VHOST_FAMILY_LABELS: dict[str, str] = {
    "portal": "Portail",
    "subdomain": "Sous-domaine",
    "public": "Public",
}

SNAPSHOT_UNAVAILABLE_RESOLUTION = (
    "Le snapshot nginx (nginx-waf-snapshot.json) est absent ou illisible — "
    "rebuild bastion-nginx et vérifiez le volume nginx-logs."
)
AGGREGATOR_UNAVAILABLE_RESOLUTION = (
    "L'agrégateur n'a pas encore produit de résumé — vérifiez que bastion-app "
    "tourne avec le job APScheduler (leader health probe, toutes les 5 min)."
)
SNAPSHOT_CHECK_CMD = (
    "ls -la ${SSO_PORTAL_DATA_DIR:-/tools/portal/data}/nginx-logs/nginx-waf-snapshot.json"
)
AGGREGATOR_CHECK_CMD = (
    "ls -la ${SSO_PORTAL_DATA_DIR:-/tools/portal/data}/nginx-logs/waf-audit-summary.json"
)

REACTIVATION_STEPS = [
    {
        "id": "order",
        "title": "Portail, puis sous-domaines",
        "detail": (
            "Activer d'abord le moteur du portail. Les apps subdomain_proxy "
            "ensuite. Le proxy public reste Off tant qu'il n'est pas armé ici."
        ),
    },
    {
        "id": "detection",
        "title": "DetectionOnly avant le blocage",
        "detail": (
            "Observer les faux positifs dans le bilan et les journaux CRS, "
            "ajouter des exclusions ciblées, puis passer le profil en On + Appliquer."
        ),
    },
    {
        "id": "disk",
        "title": "Espace disque des journaux",
        "detail": (
            "Laisser de la marge sur le volume nginx-logs : DetectionOnly écrit "
            "l'audit ModSecurity. Vérifier logrotate."
        ),
    },
]


def mode_pilotable_from_reality(active: dict[str, Any]) -> bool:
    """True when nginx actually loads the generated SecRuleEngine overlay."""
    if not active.get("verifiable"):
        return False
    return bool(active.get("engine_mode_generated_loaded"))


def mode_pilotable(active: dict[str, Any], settings: Settings | None = None) -> bool:
    if mode_pilotable_from_reality(active):
        return True
    if settings is None:
        return False
    from app.bastion.waf_reactivation import read_arm_state

    return bool(read_arm_state(settings).get("armed"))


def build_reactivation_panel(
    profile: WafProfile,
    active: dict[str, Any],
    settings: Settings,
    db: Session | None,
    *,
    export_pending: bool,
) -> dict[str, Any]:
    """Réactivation / coupure moteur CRS (portail + sous-domaines)."""
    from app.bastion.nginx_waf_reality import subdomain_engine_mode
    from app.bastion.waf_reactivation import list_subdomain_smoke_hosts, read_arm_state, read_subdomain_armed

    real = portal_engine_mode(active)
    subdomain_real = subdomain_engine_mode(active)
    pilotable = mode_pilotable_from_reality(active)
    arm = read_arm_state(settings)
    portal_armed = bool(arm.get("armed"))
    subdomain_armed = read_subdomain_armed(settings)
    subdomain_apps = list_subdomain_smoke_hosts(db) if db is not None else []
    blocked = bool(active.get("verifiable") and real == MODE_OFF and not portal_armed)
    desired_on = profile.mode in (MODE_ON, MODE_DETECTION)
    can_reactivate_portal = not portal_armed
    can_reactivate_subdomain = bool(
        portal_armed
        and real in (MODE_DETECTION, MODE_ON)
        and not subdomain_armed
        and subdomain_apps
    )
    show_tab = can_reactivate_portal or can_reactivate_subdomain or subdomain_armed
    return {
        "show": show_tab,
        "blocked": blocked,
        "pilotable": pilotable or portal_armed,
        "armed": portal_armed,
        "subdomain_armed": subdomain_armed,
        "arm": arm,
        "desired_mode": profile.mode,
        "real_mode": real,
        "subdomain_real_mode": subdomain_real,
        "subdomain_apps": subdomain_apps,
        "export_pending": bool(export_pending),
        "apply_can_change_mode": bool(portal_armed),
        "can_reactivate": can_reactivate_portal,
        "can_reactivate_portal": can_reactivate_portal,
        "can_reactivate_subdomain": can_reactivate_subdomain,
        "can_disarm": portal_armed,
        "apply_still_useful_for": [
            "Exclusions CRS (bastion-exclusions-generated.conf)",
            "Deny IP promus (waf-ip-deny.conf)",
            "Rate-limits portail",
        ],
        "title": "Réactivation ModSecurity",
        "summary": (
            "Active le moteur du portail en DetectionOnly, recharge nginx, "
            "puis contrôle /_portal_nginx_ok, /api/health et /auth/login. "
            "En cas d'échec : retour automatique à Off."
            if not portal_armed
            else (
                "Moteur portail armé. "
                + (
                    "Sous-domaines en DetectionOnly."
                    if subdomain_armed
                    else "Vous pouvez activer ModSecurity sur les applications en sous-domaine."
                )
            )
        ),
        "subdomain_summary": (
            "DetectionOnly sur les FQDN subdomain_proxy actifs "
            f"({len(subdomain_apps)} app(s)) : GET / (pas de 5xx). "
            "Retour à Off si une sonde échoue."
        ),
        "steps": list(REACTIVATION_STEPS),
        "desired_on": desired_on,
    }


def _compact_detail(text: str, max_len: int = 42) -> tuple[str, str]:
    full = text.strip()
    if len(full) <= max_len:
        return full, full
    return full[: max_len - 1].rstrip() + "…", full


def _count_unknown_host_refusals_24h(db: Session) -> int:
    """Total unknown-Host hits (PendingHost) in the last 24 h — closer to real volume than throttled audit."""
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    try:
        total = (
            db.query(func.coalesce(func.sum(PendingHost.hit_count), 0))
            .filter(PendingHost.last_seen_at >= since)
            .scalar()
        )
        return int(total or 0)
    except Exception:
        return 0


def build_unknown_host_panel(
    db: Session,
    *,
    hours: int = 24,
    geo_map: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Scanner / unknown-Host activity from app audit + PendingHost (not ModSec)."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    try:
        hits_24h = _count_unknown_host_refusals_24h(db)
        top_rows = (
            db.query(
                PendingHost.last_client_ip,
                func.sum(PendingHost.hit_count).label("hits"),
            )
            .filter(
                PendingHost.last_seen_at >= since,
                PendingHost.last_client_ip.isnot(None),
                PendingHost.last_client_ip != "",
            )
            .group_by(PendingHost.last_client_ip)
            .order_by(func.sum(PendingHost.hit_count).desc())
            .limit(5)
            .all()
        )
        audit_rows = (
            db.query(AuditLog)
            .filter(
                AuditLog.action == "access_denied_unknown_host",
                AuditLog.created_at >= since,
            )
            .order_by(AuditLog.created_at.desc())
            .limit(25)
            .all()
        )
    except Exception:
        return {
            "present": False,
            "hits_24h": 0,
            "top_ips": [],
            "recent": [],
        }

    banned_ips: set[str] = set()
    for ban in list_active_bans(db):
        if ban.target_type == "ip" and ban.target:
            banned_ips.add(str(ban.target).strip())

    top_ips = []
    for row in top_rows:
        if not row.last_client_ip:
            continue
        ip = str(row.last_client_ip)
        origin = origin_from_geoloc(ip, (geo_map or {}).get(ip))
        top_ips.append(
            {
                "ip": ip,
                "count": int(row.hits or 0),
                "banned": ip in banned_ips,
                "can_ban": bool(ip),
                "country": origin.get("country") or "",
                "flag": origin.get("flag") or "🌐",
            }
        )

    recent: list[dict[str, Any]] = []
    for row in audit_rows:
        details = row.details if isinstance(row.details, dict) else {}
        client_ip = str(row.ip_address or "—").strip() or "—"
        host = str(row.target or "—")
        uri = str(details.get("uri") or "/")[:80]
        recent.append(
            {
                "timestamp": (
                    row.created_at.isoformat()[:19].replace("T", " ")
                    if row.created_at
                    else ""
                ),
                "client_ip": client_ip,
                "host": host,
                "uri": uri,
                "rule_id": "unknown_host",
                "rule_label": UNKNOWN_HOST_FEED_RULE_LABEL,
                "rule_title": UNKNOWN_HOST_FEED_RULE_TITLE,
                "message": (details.get("user_agent") or "")[:80],
                "blocked": True,
                "critical": False,
                "families": ["Scanner"],
                "score": int(details.get("hit_count") or 0),
                "banned": client_ip in banned_ips,
                "can_ban": bool(client_ip and client_ip != "—"),
                "can_exclude": False,
                "source": "unknown_host",
            }
        )

    return {
        "present": True,
        "hits_24h": hits_24h,
        "audit_events_24h": len(audit_rows),
        "top_ips": top_ips,
        "recent": recent,
    }


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
                "action_href": "/admin/security/waf#profile",
                "action_apply": False,
            }
        if href.startswith("#"):
            return {
                "action_label": label,
                "action_href": f"/admin/security/waf{href}",
                "action_apply": False,
            }
    if page == "unified" and href and href.startswith("#"):
        return {"action_label": label, "action_href": href, "action_apply": apply}
    return {"action_label": label, "action_href": href, "action_apply": apply}


def build_protection_verdict(
    profile: WafProfile,
    active: dict[str, Any],
    *,
    export_pending: bool,
    page: str = "dashboard",
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Single admin-facing verdict from nginx reality + DB intent."""
    desired = profile.mode
    real = portal_engine_mode(active)

    armed = False
    if settings is not None:
        from app.bastion.waf_reactivation import read_arm_state

        armed = bool(read_arm_state(settings).get("armed"))

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
                "#technical",
                label="Voir le diagnostic technique",
                page=page,
            ),
        }

    if real == MODE_OFF:
        if not armed:
            return {
                "level": "inactive",
                "css": "alert-err",
                "title": "Inspection du contenu : INACTIVE",
                "message": (
                    "Moteur portal désarmé (SecRuleEngine Off). "
                    "Appliquer seul ne réactive pas ModSecurity — "
                    "utilisez l'onglet Réactivation (DetectionOnly + smoke HTTP)."
                ),
                "resolution": CRS_INACTIVE_RESOLUTION,
                **_verdict_action(
                    "#reactivation",
                    label="Réactiver le moteur",
                    page=page,
                ),
                "mode_pilotable": False,
            }
        if profile.mode != MODE_OFF or export_pending:
            return {
                "level": "inactive",
                "css": "alert-err",
                "title": "Inspection du contenu : INACTIVE",
                "message": (
                    "Moteur armé en base mais nginx est encore Off "
                    f"(profil {desired}). Attendre le watcher (≈30 s) ou forcer "
                    "sync-exports-to-confd.sh + reload sur bastion-nginx, puis Appliquer."
                ),
                "resolution": None,
                **_verdict_action(
                    None,
                    label="Appliquer / synchroniser",
                    apply=True,
                    page=page,
                ),
                "mode_pilotable": True,
            }
        return {
            "level": "inactive",
            "css": "alert-warn",
            "title": "Inspection du contenu : INACTIVE",
            "message": "Profil et nginx sont tous deux Off.",
            **_verdict_action(
                "#profile",
                label="Choisir un mode de protection",
                page=page,
            ),
            "mode_pilotable": True,
        }

    if real == MODE_DETECTION:
        if desired == MODE_DETECTION and not export_pending:
            return {
                "level": "observe",
                "css": "alert-warn",
                "title": "Inspection active — observation",
                "message": (
                    "Les requêtes sont analysées par le CRS, mais aucune n'est bloquée "
                    "(DetectionOnly)."
                ),
                **_verdict_action("#profile", label="Ajuster le profil", page=page),
            }
        if desired == MODE_ON:
            return {
                "level": "mismatch",
                "css": "alert-warn",
                "title": "Profil On — nginx encore en observation",
                "message": (
                    "Le profil enregistré demande le blocage (On), mais le moteur portal "
                    "tourne encore en DetectionOnly. Enregistrez si besoin, puis "
                    "Appliquer pour activer le blocage CRS."
                ),
                **_verdict_action(
                    None,
                    label="Appliquer le blocage",
                    apply=True,
                    page=page,
                ),
            }
        # desired Off or export drift while nginx observes
        if desired != real or export_pending:
            return {
                "level": "mismatch",
                "css": "alert-err",
                "title": "Configuration non appliquée",
                "message": (
                    "Ce que vous avez enregistré n'est pas ce qui tourne actuellement "
                    "sur nginx (profil "
                    f"{desired} vs nginx {real})."
                ),
                **_verdict_action(
                    None,
                    label="Appliquer la configuration",
                    apply=True,
                    page=page,
                ),
            }

    if real == MODE_ON and desired == MODE_ON and not export_pending:
        return {
            "level": "active",
            "css": "alert-ok",
            "title": "Inspection active",
            "message": "Blocage CRS des requêtes malveillantes.",
            "action_label": None,
            "action_href": None,
            "action_apply": False,
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

    return {
        "level": "info",
        "css": "alert-warn",
        "title": f"État nginx : {real or '—'}",
        "message": "Vérifiez l'alignement entre le profil enregistré et l'état réel.",
        **_verdict_action(
            "#technical",
            label="Voir les détails techniques",
            page=page,
        ),
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
    ip_ban_count = sum(
        1 for b in active_bans if b.target_type == "ip" and (b.target or "").strip()
    )
    promoted_ips = list_promoted_deny_ips(
        db, min_occurrences=int(profile.ip_deny_min_occurrences or 3)
    )
    unknown_refusals = _count_unknown_host_refusals_24h(db)

    crs_mode = portal_engine_mode(active)
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

    raw_layers = [
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
            "state": (
                "actif"
                if promoted_ips
                else ("app seul" if ip_ban_count else "aucune IP")
            ),
            "css": (
                "badge-ok"
                if promoted_ips
                else ("badge-warn" if ip_ban_count else "badge-muted")
            ),
            "detail": (
                f"{len(promoted_ips)} IP promue(s) vers nginx (waf-ip-deny.conf)"
                if promoted_ips
                else (
                    f"{ip_ban_count} IP en quarantaine · 0 promue(s) nginx "
                    f"(≥{int(profile.ip_deny_min_occurrences or 3)} occ. WAF ou permanent, puis Appliquer)"
                    if ip_ban_count
                    else "Aucune IP bannie"
                )
            ),
            "alert": False,
        },
        {
            "name": "Filtrage d'hôtes",
            "state": "actif",
            "css": "badge-ok",
            "detail": f"{unknown_refusals} refus / 24 h (hôtes non enregistrés)",
            "alert": unknown_refusals >= 100,
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
    compact: list[dict[str, Any]] = []
    for layer in raw_layers:
        short, full = _compact_detail(layer["detail"])
        compact.append({**layer, "detail_short": short, "detail_full": full})
    return compact


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
    crs_mode = portal_engine_mode(active)
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
                "Aucune inspection enregistrée sur la période. "
                "Vérifiez que l'audit ModSecurity est activé."
            )
        else:
            zero_explanation = "Aucune activité CRS enregistrée sur la période."

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
        "top_attackers": data.get("top_attackers") or [],
        "critical": int(data.get("critical") or 0),
        "zero_explanation": zero_explanation,
        "windows_available": list(windows.keys()),
    }


def build_attack_controls(
    settings: Settings,
    db: Session | None = None,
    *,
    geo_map: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Attack monitoring + actionable security controls (CRS + unknown host)."""
    unknown_panel: dict[str, Any] = (
        build_unknown_host_panel(db, geo_map=geo_map)
        if db is not None
        else {"present": False}
    )

    summary = read_audit_summary(settings)
    crs_present = bool(summary.get("present") and summary.get("log_available"))
    if not crs_present and not unknown_panel.get("present"):
        return {
            "present": False,
            "recent": [],
            "critical_recent": [],
            "top_attackers": [],
            "critical_24h": 0,
            "unknown_host": unknown_panel,
        }

    banned_ips: set[str] = set()
    if db is not None:
        for ban in list_active_bans(db):
            if ban.target_type == "ip" and ban.target:
                banned_ips.add(str(ban.target).strip())

    window = (summary.get("windows") or {}).get("24h") or {} if crs_present else {}
    recent_raw = summary.get("recent_events") or [] if crs_present else []
    recent: list[dict[str, Any]] = []
    for ev in reversed(recent_raw[-30:]):
        if not isinstance(ev, dict):
            continue
        if not ev.get("rule_id") or ev.get("rule_id") == "—":
            if not ev.get("blocked") and not ev.get("critical"):
                continue
        families = ev.get("families") or []
        if not families and ev.get("rule_id"):
            fam = _rule_family(str(ev.get("rule_id")))
            families = [fam]

        fam_labels = [
            RULE_FAMILY_LABELS.get(str(f), str(f).upper()) for f in families if f
        ]
        client_ip = str(ev.get("client_ip") or "—").strip() or "—"
        origin = origin_from_geoloc(
            client_ip,
            (geo_map or {}).get(client_ip) if client_ip != "—" else None,
        )
        row = {
            "timestamp": (ev.get("timestamp") or "")[:19].replace("T", " "),
            "client_ip": client_ip,
            "host": ev.get("host") or "—",
            "uri": (ev.get("uri") or "—")[:80],
            "rule_id": ev.get("rule_id") or "—",
            "message": (ev.get("message") or "")[:80],
            "blocked": bool(ev.get("blocked")),
            "critical": bool(ev.get("critical"))
            or any(f in ("sqli", "xss", "rce", "lfi") for f in families),
            "families": fam_labels,
            "score": ev.get("score") or 0,
            "banned": client_ip in banned_ips,
            "can_ban": bool(client_ip and client_ip != "—"),
            "can_exclude": str(ev.get("rule_id") or "").isdigit(),
            "source": "crs",
        }
        row["origin_network"] = origin["network"]
        row["origin_hint"] = origin["hint"]
        row["origin_flag"] = origin["flag"]
        row["origin_country"] = origin.get("country") or ""
        row["origin_country_code"] = origin.get("country_code") or ""
        row["severity"] = _event_severity(row)
        row["action_label"] = "Bloqué" if row["blocked"] else "Alerté"
        _apply_feed_target(row)
        _enrich_feed_source(row, settings=settings, db=db)
        row["inspect_b64"] = _encode_inspect_payload(row)
        recent.append(row)

    for row in unknown_panel.get("recent") or []:
        if isinstance(row, dict):
            enriched = dict(row)
            ip = str(enriched.get("client_ip") or "—")
            origin = origin_from_geoloc(
                ip, (geo_map or {}).get(ip) if ip != "—" else None
            )
            enriched.setdefault("origin_network", origin["network"])
            enriched.setdefault("origin_hint", origin["hint"])
            enriched.setdefault("origin_flag", origin["flag"])
            enriched.setdefault("origin_country", origin.get("country") or "")
            enriched.setdefault("origin_country_code", origin.get("country_code") or "")
            enriched.setdefault("severity", _event_severity(enriched))
            enriched.setdefault("action_label", "Bloqué" if enriched.get("blocked") else "Refusé")
            _apply_feed_target(enriched)
            _enrich_feed_source(enriched, settings=settings, db=db)
            enriched.setdefault("inspect_b64", _encode_inspect_payload(enriched))
            recent.append(enriched)

    recent.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
    recent = recent[:30]

    critical_recent = [r for r in recent if r.get("critical")][:15]
    attacks = [
        r
        for r in recent
        if r.get("source") == "unknown_host"
        or r.get("rule_id") != "—"
        or r.get("blocked")
    ][:15]
    if not attacks:
        attacks = recent[:15]

    merged_attackers: dict[str, int] = {}
    for atk in window.get("top_attackers") or []:
        if not isinstance(atk, dict):
            continue
        ip = str(atk.get("ip") or "—").strip() or "—"
        if ip != "—":
            merged_attackers[ip] = merged_attackers.get(ip, 0) + int(atk.get("count") or 0)
    for atk in unknown_panel.get("top_ips") or []:
        if not isinstance(atk, dict):
            continue
        ip = str(atk.get("ip") or "—").strip() or "—"
        if ip != "—":
            merged_attackers[ip] = merged_attackers.get(ip, 0) + int(atk.get("count") or 0)

    top_attackers = []
    for ip, count in sorted(merged_attackers.items(), key=lambda x: -x[1])[:5]:
        top_attackers.append(
            {
                "ip": ip,
                "count": count,
                "banned": ip in banned_ips,
                "can_ban": bool(ip and ip != "—"),
            }
        )

    return {
        "present": True,
        "recent": attacks,
        "critical_recent": critical_recent,
        "top_attackers": top_attackers,
        "critical_24h": int(window.get("critical") or 0),
        "unknown_host": unknown_panel,
    }


def _heatmap_row_key(ip: str, geo_map: dict[str, dict[str, Any]] | None) -> str:
    origin = origin_from_geoloc(ip, (geo_map or {}).get(ip))
    cc = origin.get("country_code") or ""
    country = origin.get("country") or ""
    flag = origin.get("flag") or "🌐"
    if country:
        return f"{flag} {country}"
    if cc:
        return f"{country_flag(cc)} {cc}"
    return origin.get("network") or ip


def _feed_host_key(host: str) -> str:
    text = (host or "").strip().lower().rstrip(".")
    if not text or text == "—":
        return ""
    if text.startswith("[") and "]" in text:
        return text.split("]", 1)[0] + "]"
    if text.count(":") == 1 and not text.startswith("["):
        left, right = text.rsplit(":", 1)
        if right.isdigit():
            text = left
    return text


def _resolve_vhost_family(
    host: str,
    settings: Settings,
    db: Session | None,
) -> str | None:
    name = _feed_host_key(host)
    if not name:
        return None
    portal = _feed_host_key(settings.portal_domain or "")
    if portal and (name == portal or name.endswith("." + portal)):
        return "portal"
    if db is None:
        return None
    try:
        rows = (
            db.query(App.public_fqdn, App.access_mode)
            .filter(App.enabled.is_(True), App.public_fqdn.isnot(None))
            .all()
        )
    except Exception:
        return None
    for fqdn, access_mode in rows:
        if _feed_host_key(str(fqdn or "")) == name:
            mode = str(access_mode or "")
            if mode == "subdomain_proxy":
                return "subdomain"
            if mode == "public_proxy":
                return "public"
            return "portal"
    return None


def _enrich_feed_source(
    row: dict[str, Any],
    *,
    settings: Settings | None = None,
    db: Session | None = None,
) -> None:
    source = str(row.get("source") or "crs")
    meta = FEED_SOURCE_META.get(source, FEED_SOURCE_META["crs"])
    row["source_kind"] = meta["kind"]
    row["source_label"] = meta["label"]
    row["source_title"] = meta["title"]
    if source == "crs" and settings is not None:
        fam = _resolve_vhost_family(str(row.get("host") or ""), settings, db)
        if fam:
            row["vhost_family"] = fam
            row["vhost_family_label"] = VHOST_FAMILY_LABELS.get(fam, fam)


def _apply_feed_target(row: dict[str, Any]) -> None:
    """Human-readable target column — unknown Host shows IP+path, not reverse-DNS hostname."""
    host = str(row.get("host") or "—").strip() or "—"
    uri = str(row.get("uri") or "/").strip() or "/"
    client_ip = str(row.get("client_ip") or "—").strip() or "—"
    if row.get("source") == "unknown_host":
        row["target_display"] = f"{client_ip}{uri}"
        row["target_title"] = f"Hôte HTTP : {host} · {uri}"
    else:
        combined = f"{host}{uri}" if host != "—" else uri
        row["target_display"] = combined[:120]
        row["target_title"] = combined


def _event_severity(row: dict[str, Any]) -> str:
    if row.get("critical"):
        return "critical"
    if row.get("source") == "unknown_host":
        return "medium"
    if row.get("blocked"):
        return "high"
    return "low"


def _encode_inspect_payload(row: dict[str, Any]) -> str:
    payload = {
        "timestamp": row.get("timestamp"),
        "client_ip": row.get("client_ip"),
        "host": row.get("host"),
        "uri": row.get("uri"),
        "rule_id": row.get("rule_id"),
        "rule_label": row.get("rule_label"),
        "rule_title": row.get("rule_title"),
        "message": row.get("message"),
        "blocked": row.get("blocked"),
        "critical": row.get("critical"),
        "families": row.get("families"),
        "score": row.get("score"),
        "source": row.get("source"),
        "source_kind": row.get("source_kind"),
        "source_label": row.get("source_label"),
        "vhost_family": row.get("vhost_family"),
        "vhost_family_label": row.get("vhost_family_label"),
        "origin_country": row.get("origin_country"),
        "origin_city": row.get("origin_hint"),
    }
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _compute_health_score(
    active: dict[str, Any],
    efficiency: dict[str, Any],
    layers: list[dict[str, Any]],
) -> tuple[int, list[dict[str, Any]]]:
    score = 100
    breakdown: list[dict[str, Any]] = []
    crs_mode = portal_engine_mode(active)
    if crs_mode == MODE_OFF:
        score -= 45
        breakdown.append({"label": "CRS arrêté", "points": -45})
    elif crs_mode == MODE_DETECTION:
        score -= 18
        breakdown.append({"label": "CRS en observation (DetectionOnly)", "points": -18})
    elif crs_mode is None:
        score -= 25
        breakdown.append({"label": "CRS non vérifiable", "points": -25})
    critical = int(efficiency.get("critical") or 0)
    if critical:
        delta = min(25, critical * 4)
        score -= delta
        breakdown.append(
            {
                "label": f"{critical} alerte(s) critique(s) · 24 h",
                "points": -delta,
            }
        )
    for layer in layers:
        if layer.get("alert"):
            score -= 8
            breakdown.append(
                {
                    "label": layer["name"],
                    "points": -8,
                    "detail": layer.get("detail_full") or layer.get("detail"),
                }
            )
    return max(0, min(100, score)), breakdown


def _blocks_trend_pct(series_24h: list[dict[str, Any]], blocks: int) -> float | None:
    if not series_24h:
        return None
    mid = max(1, len(series_24h) // 2)
    prev = sum(int(p.get("detections") or 0) for p in series_24h[:mid])
    curr = sum(int(p.get("detections") or 0) for p in series_24h[mid:])
    if prev == 0 and curr == 0:
        return 0.0 if blocks == 0 else 100.0
    if prev == 0:
        return 100.0
    return round(((curr - prev) / prev) * 100, 1)


def _live_suspicious_count(
    series_24h: list[dict[str, Any]], unknown_hits: int
) -> int:
    live = sum(int(p.get("detections") or 0) for p in series_24h[-3:])
    return live + min(unknown_hits, 9999)


def build_executive_summary(
    settings: Settings,
    active: dict[str, Any],
    efficiency: dict[str, Any],
    attack_controls: dict[str, Any],
    unknown_host_panel: dict[str, Any],
    layers: list[dict[str, Any]],
) -> dict[str, Any]:
    summary = read_audit_summary(settings)
    series_24h = (summary.get("series") or {}).get("24h") or []
    inspected = int(efficiency.get("inspected") or 0) if efficiency.get("present") else 0
    blocks = int(efficiency.get("blocks") or 0) if efficiency.get("present") else 0
    trend = _blocks_trend_pct(series_24h, blocks)
    unknown_hits = int(unknown_host_panel.get("hits_24h") or 0)
    live_suspicious = _live_suspicious_count(series_24h, unknown_hits) if efficiency.get("present") else unknown_hits
    health, health_breakdown = _compute_health_score(active, efficiency, layers)
    return {
        "present": efficiency.get("present") or unknown_host_panel.get("present"),
        "inspected": inspected,
        "blocks": blocks,
        "blocks_trend_pct": trend,
        "health_score": health,
        "health_breakdown": health_breakdown,
        "health_gauge_svg": render_health_gauge(health),
        "live_suspicious": live_suspicious,
        "generated_at": efficiency.get("generated_at"),
    }


def _build_heatmap_matrix(
    settings: Settings,
    db: Session | None,
    *,
    geo_map: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[list[int]], list[str], list[str]]:
    summary = read_audit_summary(settings)
    recent = summary.get("recent_events") or []
    col_labels = [f"{h:02d}h" for h in range(24)]
    network_counts: dict[str, dict[int, int]] = {}
    for ev in recent:
        if not isinstance(ev, dict):
            continue
        ip = str(ev.get("client_ip") or "").strip()
        if not ip:
            continue
        net = _heatmap_row_key(ip, geo_map)
        ts = str(ev.get("timestamp") or "")
        hour = 0
        if len(ts) >= 13:
            try:
                hour = int(ts[11:13])
            except ValueError:
                hour = 0
        bucket = network_counts.setdefault(net, {})
        bucket[hour] = bucket.get(hour, 0) + 1
    if db is not None:
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        rows = (
            db.query(PendingHost.last_client_ip, PendingHost.hit_count, PendingHost.last_seen_at)
            .filter(PendingHost.last_seen_at >= since, PendingHost.last_client_ip.isnot(None))
            .all()
        )
        for row in rows:
            ip = str(row.last_client_ip or "").strip()
            if not ip:
                continue
            net = _heatmap_row_key(ip, geo_map)
            hour = row.last_seen_at.hour if row.last_seen_at else 0
            bucket = network_counts.setdefault(net, {})
            bucket[hour] = bucket.get(hour, 0) + int(row.hit_count or 1)
    if not network_counts:
        return [], [], col_labels
    ranked = sorted(
        network_counts.items(),
        key=lambda x: sum(x[1].values()),
        reverse=True,
    )[:6]
    row_labels = [label for label, _ in ranked]
    matrix = []
    for _, hours in ranked:
        matrix.append([hours.get(h, 0) for h in range(24)])
    return matrix, row_labels, col_labels


def build_quarantine_panel(
    db: Session,
    *,
    geo_map: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    bans = list_active_bans(db)
    rows: list[dict[str, Any]] = []
    for ban in bans[:20]:
        if ban.target_type != "ip" or not ban.target:
            continue
        origin = origin_from_geoloc(str(ban.target), (geo_map or {}).get(str(ban.target)))
        rows.append(
            {
                "id": ban.id,
                "ip": str(ban.target),
                "rule_type": ban.rule_type or "manual",
                "rule_type_label": BAN_RULE_TYPE_LABELS.get(
                    ban.rule_type or "manual", ban.rule_type or "manual"
                ),
                "reason": (ban.reason or "")[:80],
                "expires_at": (
                    ban.expires_at.isoformat()[:16].replace("T", " ")
                    if ban.expires_at
                    else None
                ),
                "permanent": bool(ban.permanent),
                "origin_hint": origin["hint"],
                "flag": origin["flag"],
                "country": origin.get("country") or "",
            }
        )
    return {"present": True, "count": len(rows), "rows": rows}


def build_quick_controls(
    db: Session,
    profile: WafProfile,
    active: dict[str, Any],
    settings: Settings,
) -> list[dict[str, Any]]:
    policy = get_or_create_policy(db)
    crs_mode = portal_engine_mode(active)
    crs_on = crs_mode == MODE_ON
    geoloc_on = resolve_ip_geoloc_enabled(settings, profile)
    env_geoloc = bool(getattr(settings, "ip_geoloc_enabled", True))
    return [
        {
            "id": "crs",
            "label": "Inspection CRS",
            "enabled": crs_on,
            "detail": "Blocage ModSecurity/OWASP CRS",
            "toggle": "crs",
            "readonly": crs_mode is None,
        },
        {
            "id": "bruteforce",
            "label": "Anti-bruteforce",
            "enabled": bool(policy.enabled),
            "detail": "Moteur de banning applicatif",
            "toggle": "bruteforce",
            "readonly": False,
        },
        {
            "id": "geoloc",
            "label": "Géolocalisation IP",
            "enabled": geoloc_on,
            "detail": (
                "ip-api.com · drapeaux et heatmap par pays"
                if env_geoloc
                else "Verrouillée (IP_GEOLOC_ENABLED=false)"
            ),
            "toggle": "geoloc" if env_geoloc else None,
            "readonly": not env_geoloc,
        },
        {
            "id": "rate_limit",
            "label": "Rate limiting",
            "enabled": True,
            "detail": (
                f"{profile.portal_login_rate} r/s login · "
                f"{profile.portal_api_rate} r/s API"
            ),
            "toggle": None,
            "readonly": True,
        },
    ]


def build_threat_intel_visuals(
    settings: Settings,
    active: dict[str, Any],
    efficiency: dict[str, Any],
    db: Session | None = None,
    *,
    geo_map: dict[str, dict[str, Any]] | None = None,
    geoloc_enabled: bool = True,
) -> dict[str, Any]:
    """Threat intelligence charts for Sentinel dashboard."""
    if not efficiency.get("present"):
        panel = _empty_panel(
            title="Threat Intelligence",
            message=efficiency.get("message") or "Données indisponibles",
            resolution=efficiency.get("resolution") or AGGREGATOR_UNAVAILABLE_RESOLUTION,
            variant="unavailable",
            width=560,
            height=200,
        )
        return {
            "traffic_area_svg": panel,
            "origin_heatmap_svg": panel,
            "owasp_rules_svg": panel,
        }
    summary = read_audit_summary(settings)
    series_24h = (summary.get("series") or {}).get("24h") or []
    window = (summary.get("windows") or {}).get("24h") or {}
    top_rules = [
        {"label": f"{r.get('rule_id')} · {(r.get('label') or '')[:20]}", "count": r.get("count")}
        for r in (window.get("top_rules") or [])[:5]
    ]
    matrix, row_labels, col_labels = _build_heatmap_matrix(
        settings, db, geo_map=geo_map
    )
    heatmap_title = (
        "Origine des attaques (pays × heure)"
        if geoloc_enabled
        else "Origine des attaques (réseaux /24 × heure)"
    )
    measured_zero = efficiency.get("status") == "measured_zero"
    empty_variant = "measured_zero" if measured_zero else "empty"
    return {
        "traffic_area_svg": render_dual_area_chart(
            series_24h,
            title="Trafic vs tentatives d'intrusion (24 h)",
            empty_variant=empty_variant,
        ),
        "origin_heatmap_svg": render_attack_heatmap(
            matrix,
            row_labels=row_labels,
            col_labels=col_labels,
            title=heatmap_title,
        ),
        "owasp_rules_svg": render_owasp_bars(
            top_rules,
            title="Top 5 règles OWASP déclenchées",
        ),
    }


def build_efficiency_visuals(
    settings: Settings,
    active: dict[str, Any],
    efficiency: dict[str, Any],
) -> dict[str, Any]:
    """Pre-render SVG charts for the Bilan tab."""
    if not efficiency.get("present"):
        msg = efficiency.get("message") or "Données indisponibles"
        res = efficiency.get("resolution") or AGGREGATOR_UNAVAILABLE_RESOLUTION
        panel = _empty_panel(
            title="Données indisponibles",
            message=msg,
            resolution=res,
            variant="unavailable",
            width=360,
            height=180,
        )
        return {
            "status": "unavailable",
            "detections_hourly_svg": panel,
            "detections_daily_svg": panel,
            "top_rules_svg": panel,
            "top_hosts_svg": panel,
            "families_svg": panel,
        }

    if not active.get("verifiable"):
        panel = _empty_panel(
            title="Non vérifiable",
            message="Snapshot nginx absent — séries temporelles non interprétables.",
            resolution=SNAPSHOT_UNAVAILABLE_RESOLUTION,
            variant="unverifiable",
            width=360,
            height=180,
        )
        return {
            "status": "unverifiable",
            "detections_hourly_svg": panel,
            "detections_daily_svg": panel,
            "top_rules_svg": panel,
            "top_hosts_svg": panel,
            "families_svg": panel,
        }

    summary = read_audit_summary(settings)
    series = summary.get("series") or {}
    window = (summary.get("windows") or {}).get("24h") or {}
    series_24h = series.get("24h") or []
    series_7d = series.get("7d") or []
    measured_zero = efficiency.get("status") == "measured_zero"

    top_rules = [
        {"label": f"{r.get('rule_id')} · {r.get('label')}", "count": r.get("count")}
        for r in (window.get("top_rules") or [])
    ]
    top_hosts = [
        {"label": h.get("host"), "count": h.get("count")} for h in (window.get("top_hosts") or [])
    ]
    families = window.get("rule_families") or []

    empty_variant = "measured_zero" if measured_zero else "empty"
    return {
        "status": efficiency.get("status") or "ok",
        "detections_hourly_svg": render_series_chart(
            series_24h,
            title="Détections / heure (24 h)",
            empty_variant=empty_variant,
            empty_message="Aucune détection sur 24 h",
        ),
        "detections_daily_svg": render_series_chart(
            series_7d,
            title="Détections / jour (7 j)",
            empty_variant=empty_variant,
            empty_message="Aucune détection sur 7 j",
        ),
        "top_rules_svg": render_horizontal_bars(
            top_rules,
            label_key="label",
            title="Top 5 règles CRS",
        ),
        "top_hosts_svg": render_horizontal_bars(
            top_hosts,
            label_key="label",
            title="Top 5 hosts",
        ),
        "families_svg": render_family_breakdown(families),
    }


def build_diagnostic_panel(
    settings: Settings,
    active: dict[str, Any],
    generated: dict[str, Any],
    headers_panel: dict[str, Any],
) -> dict[str, Any]:
    snap_path = resolve_nginx_waf_snapshot_path(settings)
    snap_present = snap_path.is_file()
    snap_age = None
    snap_generated_at = None
    if snap_present:
        try:
            import json as _json
            from datetime import datetime as _dt

            raw = _json.loads(snap_path.read_text(encoding="utf-8"))
            snap_generated_at = raw.get("generated_at")
            if snap_generated_at:
                ts = _dt.fromisoformat(str(snap_generated_at).replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                snap_age = int((datetime.now(timezone.utc) - ts).total_seconds() // 60)
        except (OSError, ValueError, TypeError):
            pass

    agg_state = read_aggregator_state(settings)
    summary_path = resolve_audit_summary_path(settings)
    summary = read_audit_summary(settings)
    log_path = resolve_modsec_audit_log_path(settings)

    checks = [
        {
            "name": "Snapshot nginx",
            "status": "ok" if active.get("verifiable") else "warn",
            "detail": (
                f"Présent — généré {snap_generated_at} ({snap_age} min)"
                if snap_present and snap_generated_at
                else ("Fichier présent mais illisible" if snap_present else "Absent")
            ),
            "path": str(snap_path),
            "action": SNAPSHOT_CHECK_CMD if not active.get("verifiable") else None,
            "resolution": SNAPSHOT_UNAVAILABLE_RESOLUTION if not active.get("verifiable") else None,
        },
        {
            "name": "Agrégateur audit",
            "status": "ok" if summary.get("present") else "warn",
            "detail": (
                f"Dernier résumé : {summary.get('generated_at') or '—'}"
                if summary.get("present")
                else "Jamais exécuté"
            ),
            "path": str(summary_path),
            "action": AGGREGATOR_CHECK_CMD if not summary.get("present") else None,
            "resolution": AGGREGATOR_UNAVAILABLE_RESOLUTION if not summary.get("present") else None,
        },
        {
            "name": "Journal modsec_audit.log",
            "status": "ok" if log_path.is_file() else "muted",
            "detail": "Présent" if log_path.is_file() else "Absent (normal si CRS arrêté)",
            "path": str(log_path),
            "action": None,
            "resolution": None,
        },
        {
            "name": "En-têtes de sécurité",
            "status": "ok" if headers_panel.get("present") else "warn",
            "detail": (
                f"{len(headers_panel.get('headers') or [])} en-tête(s) lus"
                if headers_panel.get("present")
                else "Non vérifiable sans snapshot"
            ),
            "path": headers_panel.get("path") or "—",
            "action": SNAPSHOT_CHECK_CMD if not headers_panel.get("present") else None,
            "resolution": SNAPSHOT_UNAVAILABLE_RESOLUTION if not headers_panel.get("present") else None,
        },
    ]

    offset = (agg_state.get("log_file_state") or {}).get("offset")
    return {
        "checks": checks,
        "aggregator_state_path": str(resolve_aggregator_state_path(settings)),
        "aggregator_offset": offset,
        "aggregator_state_present": agg_state.get("present"),
        "summary_path": str(summary_path),
        "last_apply_at": generated.get("last_apply_at"),
    }


def _json_safe(value: Any) -> Any:
    """Recursively make a value JSON-serializable (no secrets, no ORM objects)."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return str(value)


def build_waf_diagnostic_export(
    *,
    desired: dict[str, Any],
    generated: dict[str, Any],
    active: dict[str, Any],
    pending_diffs: list[dict[str, Any]],
    export_pending: bool,
    control_effect: dict[str, Any],
    security_headers_panel: dict[str, Any],
    diagnostic: dict[str, Any],
    verdict: dict[str, Any],
    reality_warnings: list[str] | None = None,
    reload_confirmed: bool | None = None,
) -> dict[str, Any]:
    """Full diagnostic payload: expected (DB) vs generated vs real nginx.

    Safe to paste into a support chat — no secrets, paths and modes only.
    """
    expected_mode = desired.get("mode")
    real_mode = portal_engine_mode(active)
    export_mode = generated.get("mode") if generated.get("present") else None

    mismatches: list[dict[str, Any]] = []
    if expected_mode and real_mode and expected_mode != real_mode:
        mismatches.append(
            {
                "field": "mode",
                "expected": expected_mode,
                "actual": real_mode,
                "source": "db_vs_nginx",
            }
        )
    if (
        desired.get("anomaly_threshold") is not None
        and active.get("verifiable")
        and active.get("aggregate_threshold") is not None
        and int(desired["anomaly_threshold"]) != int(active["aggregate_threshold"])
    ):
        mismatches.append(
            {
                "field": "anomaly_threshold",
                "expected": desired.get("anomaly_threshold"),
                "actual": active.get("aggregate_threshold"),
                "source": "db_vs_nginx",
            }
        )
    for d in pending_diffs or []:
        mismatches.append(
            {
                "field": d.get("field") or d.get("label"),
                "expected": d.get("db"),
                "actual": d.get("export"),
                "source": "db_vs_export",
            }
        )

    payload = {
        "schema_version": 1,
        "kind": "bastion-waf-diagnostic",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "purpose": (
            "Export de diagnostic WAF : configuration attendue (DB) vs export généré "
            "vs état réellement actif (snapshot nginx). À coller pour le debug."
        ),
        "verdict": {
            "level": verdict.get("level"),
            "title": verdict.get("title"),
            "message": verdict.get("message"),
            "resolution": verdict.get("resolution"),
        },
        "alignment": {
            "export_pending": bool(export_pending),
            "reload_confirmed": reload_confirmed,
            "control_effect": _json_safe(control_effect),
            "mismatches": mismatches,
            "reality_warnings": list(reality_warnings or []),
        },
        "expected": {
            "source": "database_waf_profile",
            "profile": _json_safe(desired),
        },
        "generated": {
            "source": "exports/modsecurity/waf-effective-status.json",
            "present": bool(generated.get("present")),
            "status": _json_safe(
                {
                    k: generated.get(k)
                    for k in (
                        "present",
                        "path",
                        "mode",
                        "anomaly_threshold",
                        "profile_name",
                        "ip_deny_count",
                        "ip_deny_min_occurrences",
                        "exclusion_count",
                        "exclusion_rule_ids",
                        "portal_login_rate",
                        "portal_api_rate",
                        "portal_login_burst",
                        "portal_api_burst",
                        "last_apply_at",
                        "last_apply_by",
                        "last_apply_nginx_t_ok",
                        "last_apply_nginx_t_skipped",
                        "last_apply_nginx_t_detail",
                    )
                    if k in generated or k in ("present", "path", "mode")
                }
            ),
        },
        "actual": {
            "source": "nginx-waf-snapshot.json",
            "verifiable": bool(active.get("verifiable")),
            "error": active.get("error"),
            "snapshot_path": active.get("snapshot_path"),
            "generated_at": active.get("generated_at"),
            "aggregate_mode": active.get("aggregate_mode"),
            "portal_mode": portal_engine_mode(active),
            "aggregate_threshold": active.get("aggregate_threshold"),
            "engine_mode_generated_loaded": active.get("engine_mode_generated_loaded"),
            "crs_setup_generated_loaded": active.get("crs_setup_generated_loaded"),
            "families": _json_safe(active.get("families")),
            "column_title": active.get("column_title"),
        },
        "security_headers": _json_safe(
            {
                "present": security_headers_panel.get("present"),
                "path": security_headers_panel.get("path"),
                "header_count": len(security_headers_panel.get("headers") or []),
                "headers": security_headers_panel.get("headers") or [],
                "source_note": security_headers_panel.get("source_note"),
            }
        ),
        "sources": {
            "checks": _json_safe(diagnostic.get("checks") or []),
            "aggregator_state_path": diagnostic.get("aggregator_state_path"),
            "aggregator_offset": diagnostic.get("aggregator_offset"),
            "aggregator_state_present": diagnostic.get("aggregator_state_present"),
            "summary_path": diagnostic.get("summary_path"),
        },
    }
    return payload


def format_waf_diagnostic_export_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def build_waf_readability_context(
    db: Session,
    settings: Settings,
    profile: WafProfile,
    active: dict[str, Any],
    headers_panel: dict[str, Any],
    *,
    export_pending: bool,
    page: str = "unified",
    generated: dict[str, Any] | None = None,
) -> dict[str, Any]:
    verdict = build_protection_verdict(
        profile, active, export_pending=export_pending, page=page, settings=settings
    )
    layers = build_protection_layers(db, profile, active, headers_panel)
    efficiency_24h = build_efficiency_panel(settings, active, window="24h")
    efficiency_7d = build_efficiency_panel(settings, active, window="7d")
    audit_summary = read_audit_summary(settings)
    dashboard_ips = collect_waf_dashboard_ips(settings, db, summary=audit_summary)
    geoloc_enabled = resolve_ip_geoloc_enabled(settings, profile)
    geo_map = (
        lookup_ip_origins(settings, dashboard_ips, profile=profile)
        if geoloc_enabled
        else {}
    )
    visuals = build_efficiency_visuals(settings, active, efficiency_24h)
    attack_controls = build_attack_controls(settings, db, geo_map=geo_map)
    unknown_host_panel = attack_controls.get("unknown_host") or build_unknown_host_panel(
        db, geo_map=geo_map
    )
    reactivation = build_reactivation_panel(
        profile, active, settings, db, export_pending=export_pending
    )
    diagnostic = build_diagnostic_panel(
        settings, active, generated or {}, headers_panel
    )
    executive = build_executive_summary(
        settings, active, efficiency_24h, attack_controls, unknown_host_panel, layers
    )
    threat_intel = build_threat_intel_visuals(
        settings,
        active,
        efficiency_24h,
        db,
        geo_map=geo_map,
        geoloc_enabled=geoloc_enabled,
    )
    quarantine = build_quarantine_panel(db, geo_map=geo_map)
    quick_controls = build_quick_controls(db, profile, active, settings)
    apply_enabled = bool(export_pending) or bool(
        verdict.get("action_apply") and reactivation.get("armed")
    )
    return {
        "verdict": verdict,
        "protection_layers": layers,
        "efficiency": efficiency_24h,
        "efficiency_7d": efficiency_7d,
        "efficiency_visuals": visuals,
        "attack_controls": attack_controls,
        "unknown_host_panel": unknown_host_panel,
        "executive_summary": executive,
        "threat_intel": threat_intel,
        "quarantine_panel": quarantine,
        "quick_controls": quick_controls,
        "ip_geolocation": {
            "enabled": geoloc_enabled,
            "profile_enabled": bool(getattr(profile, "ip_geoloc_enabled", True)),
            "env_locked": not bool(getattr(settings, "ip_geoloc_enabled", True)),
            "resolved": len(geo_map),
            "provider": "ip-api.com",
        },
        "security_policy_enabled": get_or_create_policy(db).enabled,
        "reactivation": reactivation,
        "apply_enabled": apply_enabled,
        "mode_pilotable": reactivation.get("pilotable"),
        "diagnostic": diagnostic,
    }
