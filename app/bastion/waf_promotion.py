"""Assisted DetectionOnly → On promotion readiness (admin confirmation required).

Observes ModSecurity audit aggregates — never auto-flips SecRuleEngine without
an explicit Admin confirm + smoke path.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.bastion.modsec_audit_aggregator import read_audit_summary
from app.bastion.nginx_waf_export import MODE_DETECTION, MODE_ON
from app.bastion.waf_reactivation import read_arm_state, read_subdomain_armed
from app.sso_settings import Settings

# Soft gates — critical detections over the observation window block "ready".
DEFAULT_WINDOW = "7d"
MAX_CRITICAL_READY = 0
# Prefer at least one day of aggregator data before calling it "ready".
MIN_SUMMARY_AGE_HOURS = 24


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def _window_stats(summary: dict[str, Any], window: str) -> dict[str, int]:
    windows = summary.get("windows") or {}
    data = windows.get(window) or windows.get("24h") or {}
    return {
        "inspected": int(data.get("inspected") or 0),
        "detections": int(data.get("detections") or 0),
        "blocks": int(data.get("blocks") or 0),
        "critical": int(data.get("critical") or 0),
    }


def _top_noisy_rules(summary: dict[str, Any], *, limit: int = 5) -> list[dict[str, Any]]:
    windows = summary.get("windows") or {}
    data = windows.get(DEFAULT_WINDOW) or windows.get("24h") or {}
    rules = data.get("top_rules") or summary.get("top_rules") or []
    out: list[dict[str, Any]] = []
    for item in rules[:limit]:
        if not isinstance(item, dict):
            continue
        rid = str(item.get("rule_id") or item.get("id") or "").strip()
        if not rid:
            continue
        out.append(
            {
                "rule_id": rid,
                "label": str(item.get("label") or item.get("message") or "")[:80],
                "count": int(item.get("count") or 0),
            }
        )
    return out


def evaluate_promotion_readiness(
    settings: Settings,
    *,
    family: str,
) -> dict[str, Any]:
    """Return readiness for portal or subdomain DetectionOnly → On."""
    fam = (family or "portal").strip().lower()
    if fam not in {"portal", "subdomain"}:
        fam = "portal"

    arm = read_arm_state(settings)
    summary = read_audit_summary(settings)
    stats = _window_stats(summary, DEFAULT_WINDOW) if summary.get("present") else {
        "inspected": 0,
        "detections": 0,
        "blocks": 0,
        "critical": 0,
    }
    noisy = _top_noisy_rules(summary) if summary.get("present") else []
    generated_at = _parse_iso(str(summary.get("generated_at") or ""))
    age_hours: float | None = None
    if generated_at is not None:
        age_hours = max(
            0.0,
            (datetime.now(timezone.utc) - generated_at.astimezone(timezone.utc)).total_seconds()
            / 3600.0,
        )

    base = {
        "family": fam,
        "window": DEFAULT_WINDOW,
        "stats": stats,
        "noisy_rules": noisy,
        "summary_present": bool(summary.get("present")),
        "summary_age_hours": round(age_hours, 1) if age_hours is not None else None,
        "max_critical": MAX_CRITICAL_READY,
        "auto_promote": False,  # always require Admin confirm
    }

    if fam == "portal":
        return _portal_readiness(arm, base, stats=stats, age_hours=age_hours)
    return _subdomain_readiness(arm, settings, base, stats=stats, age_hours=age_hours)


def _portal_readiness(
    arm: dict[str, Any],
    base: dict[str, Any],
    *,
    stats: dict[str, int],
    age_hours: float | None,
) -> dict[str, Any]:
    if not arm.get("armed"):
        return {
            **base,
            "status": "not_applicable",
            "ready": False,
            "can_promote": False,
            "title": "Promotion portal indisponible",
            "detail": "Réactiver d'abord le portail en DetectionOnly.",
        }
    target = str(arm.get("target_mode") or MODE_DETECTION)
    if target == MODE_ON:
        return {
            **base,
            "status": "already_on",
            "ready": False,
            "can_promote": False,
            "title": "Portal déjà en On",
            "detail": "Cible arm.json = On — pas de promotion DetectionOnly → On.",
        }
    return _score_observation(
        base,
        stats=stats,
        age_hours=age_hours,
        title_ready="Portal prêt à passer en On (blocage)",
        title_blocked="Portal : trop de détections critiques",
        title_observing="Portal en observation (DetectionOnly)",
    )


def _subdomain_readiness(
    arm: dict[str, Any],
    settings: Settings,
    base: dict[str, Any],
    *,
    stats: dict[str, int],
    age_hours: float | None,
) -> dict[str, Any]:
    if not arm.get("armed"):
        return {
            **base,
            "status": "not_applicable",
            "ready": False,
            "can_promote": False,
            "title": "Promotion subdomain indisponible",
            "detail": "Armer le portail avant les sous-domaines.",
        }
    if not read_subdomain_armed(settings):
        return {
            **base,
            "status": "not_applicable",
            "ready": False,
            "can_promote": False,
            "title": "Promotion subdomain indisponible",
            "detail": "Réactiver subdomain en DetectionOnly d'abord.",
        }
    sub = arm.get("subdomain") if isinstance(arm.get("subdomain"), dict) else {}
    target = str(sub.get("target_mode") or MODE_DETECTION)
    if target == MODE_ON:
        return {
            **base,
            "status": "already_on",
            "ready": False,
            "can_promote": False,
            "title": "Subdomain déjà en On",
            "detail": "Cible subdomain = On.",
        }
    return _score_observation(
        base,
        stats=stats,
        age_hours=age_hours,
        title_ready="Subdomain prêt à passer en On (blocage)",
        title_blocked="Subdomain : trop de détections critiques",
        title_observing="Subdomain en observation (DetectionOnly)",
    )


def _score_observation(
    base: dict[str, Any],
    *,
    stats: dict[str, int],
    age_hours: float | None,
    title_ready: str,
    title_blocked: str,
    title_observing: str,
) -> dict[str, Any]:
    critical = int(stats.get("critical") or 0)
    detections = int(stats.get("detections") or 0)
    if not base.get("summary_present"):
        return {
            **base,
            "status": "observing",
            "ready": False,
            "can_promote": True,  # allow promote with warning (admin owns risk)
            "title": title_observing,
            "detail": (
                "Pas encore de résumé d'audit ModSecurity — promotion possible "
                "mais sans signal d'observation. Préférer attendre l'agrégateur."
            ),
        }
    if critical > MAX_CRITICAL_READY:
        return {
            **base,
            "status": "blocked",
            "ready": False,
            "can_promote": False,
            "title": title_blocked,
            "detail": (
                f"{critical} détection(s) critique(s) sur {DEFAULT_WINDOW} "
                f"(max toléré : {MAX_CRITICAL_READY}). Créer des exclusions "
                "ou investiguer avant de bloquer."
            ),
        }
    short = age_hours is not None and age_hours < MIN_SUMMARY_AGE_HOURS
    if short:
        return {
            **base,
            "status": "observing",
            "ready": False,
            "can_promote": True,
            "title": title_observing,
            "detail": (
                f"Fenêtre encore courte ({age_hours:.0f} h < {MIN_SUMMARY_AGE_HOURS} h). "
                f"{detections} détection(s), {critical} critique(s) sur {DEFAULT_WINDOW}. "
                "Promotion autorisée avec confirmation explicite."
            ),
        }
    return {
        **base,
        "status": "ready",
        "ready": True,
        "can_promote": True,
        "title": title_ready,
        "detail": (
            f"Observation OK : {detections} détection(s), {critical} critique(s) "
            f"sur {DEFAULT_WINDOW}. Confirmer pour basculer en On (smoke + rollback)."
        ),
    }


def build_promotion_panel(settings: Settings) -> dict[str, Any]:
    portal = evaluate_promotion_readiness(settings, family="portal")
    subdomain = evaluate_promotion_readiness(settings, family="subdomain")
    return {
        "portal": portal,
        "subdomain": subdomain,
        "any_ready": bool(portal.get("ready") or subdomain.get("ready")),
        "any_can_promote": bool(
            portal.get("can_promote") or subdomain.get("can_promote")
        ),
    }
