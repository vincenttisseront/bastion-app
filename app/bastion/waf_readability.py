"""WAF admin page readability — verdict, protection layers, efficiency (lot 4)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

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
from app.bastion.nginx_waf_reality import resolve_nginx_waf_snapshot_path
from app.bastion.waf_charts import (
    render_family_breakdown,
    render_horizontal_bars,
    render_series_chart,
    _empty_panel,
)
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
SNAPSHOT_CHECK_CMD = (
    "ls -la ${SSO_PORTAL_DATA_DIR:-/tools/portal/data}/nginx-logs/nginx-waf-snapshot.json"
)
AGGREGATOR_CHECK_CMD = (
    "ls -la ${SSO_PORTAL_DATA_DIR:-/tools/portal/data}/nginx-logs/waf-audit-summary.json"
)


def _compact_detail(text: str, max_len: int = 42) -> tuple[str, str]:
    full = text.strip()
    if len(full) <= max_len:
        return full, full
    return full[: max_len - 1].rstrip() + "…", full


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
                "#technical",
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
                "#technical",
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
        "top_attackers": data.get("top_attackers") or [],
        "critical": int(data.get("critical") or 0),
        "zero_explanation": zero_explanation,
        "windows_available": list(windows.keys()),
    }


def build_attack_controls(settings: Settings, db: Session | None = None) -> dict[str, Any]:
    """Attack monitoring + actionable security controls (ban / exclude)."""
    summary = read_audit_summary(settings)
    if not summary.get("present") or not summary.get("log_available"):
        return {
            "present": False,
            "recent": [],
            "critical_recent": [],
            "top_attackers": [],
            "critical_24h": 0,
        }

    banned_ips: set[str] = set()
    if db is not None:
        for ban in list_active_bans(db):
            if ban.target_type == "ip" and ban.target:
                banned_ips.add(str(ban.target).strip())

    window = (summary.get("windows") or {}).get("24h") or {}
    recent_raw = summary.get("recent_events") or []
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
        }
        recent.append(row)

    critical_recent = [r for r in recent if r.get("critical")][:15]
    attacks = [r for r in recent if r.get("rule_id") != "—" or r.get("blocked")][:15]
    if not attacks:
        attacks = recent[:15]

    top_attackers = []
    for atk in window.get("top_attackers") or []:
        if not isinstance(atk, dict):
            continue
        ip = str(atk.get("ip") or "—").strip() or "—"
        top_attackers.append(
            {
                "ip": ip,
                "count": int(atk.get("count") or 0),
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

    empty_variant = "measured_zero" if measured_zero else "measured_zero"
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
    real_mode = active.get("aggregate_mode") if active.get("verifiable") else None
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
        profile, active, export_pending=export_pending, page=page
    )
    layers = build_protection_layers(db, profile, active, headers_panel)
    efficiency_24h = build_efficiency_panel(settings, active, window="24h")
    efficiency_7d = build_efficiency_panel(settings, active, window="7d")
    visuals = build_efficiency_visuals(settings, active, efficiency_24h)
    attack_controls = build_attack_controls(settings, db)
    diagnostic = build_diagnostic_panel(
        settings, active, generated or {}, headers_panel
    )
    return {
        "verdict": verdict,
        "protection_layers": layers,
        "efficiency": efficiency_24h,
        "efficiency_7d": efficiency_7d,
        "efficiency_visuals": visuals,
        "attack_controls": attack_controls,
        "diagnostic": diagnostic,
    }
