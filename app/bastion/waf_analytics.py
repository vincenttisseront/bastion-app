"""WAF Bilan analytics (v1.1) — KPIs from RelevantOnly audit + profile state.

Volume metrics are audit events only (never nginx access.log).
Blocked intents prefer disruptive rule signals, with anomaly threshold as CRS net.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.bastion.modsec_audit_aggregator import (
    read_audit_summary,
    resolve_audit_summary_path,
)
from app.bastion.nginx_waf_reality import portal_engine_mode, read_nginx_waf_reality
from app.bastion.packs.catalog import PACK_CATALOG
from app.bastion.waf_virtual_patches import (
    PACK_MODE_DETECTION,
    PACK_MODE_ON,
    build_audit_health,
    profile_pack_mode,
    _audit_hints_for_pack,
)
from app.models import App, AuditLog, WafExclusion, WafProfile
from app.sso_settings import Settings

# CRS inbound/outbound anomaly "block" marker rules.
_CRS_ANOMALY_BLOCK_IDS = frozenset({"949110", "949111", "959100", "959101"})
_DISRUPTIVE_MSG = ("deny", "denied", "block", "drop", "access denied")


def _fmt_count(n: int) -> str:
    try:
        from app.bastion.waf_readability import format_kpi_count

        return format_kpi_count(int(n))
    except Exception:  # noqa: BLE001
        return str(int(n))


def event_block_intent(
    event: dict[str, Any],
    *,
    anomaly_threshold: int = 5,
) -> bool:
    """True when the event would reject traffic if the engine/pack were On.

    Primary: disruptive signals (deny/block text, CRS anomaly block ids,
    Bastion virtual-patch ids). Secondary: inbound anomaly score ≥ threshold.
    """
    if not isinstance(event, dict):
        return False
    if event.get("blocked"):
        return True
    msg = str(event.get("message") or "").lower()
    if any(tok in msg for tok in _DISRUPTIVE_MSG):
        return True
    rule_ids = [str(r).strip() for r in (event.get("rule_ids") or []) if r]
    if any(rid in _CRS_ANOMALY_BLOCK_IDS for rid in rule_ids):
        return True
    if any(rid.startswith("100096") for rid in rule_ids):
        return True
    try:
        score = int(event.get("score") or 0)
    except (TypeError, ValueError):
        score = 0
    threshold = max(1, int(anomaly_threshold or 5))
    if score >= threshold:
        return True
    # High-severity CRS attack classes without explicit deny text (DetectionOnly).
    if event.get("critical") and score >= 2:
        return True
    return False


def _window_24h(summary: dict[str, Any]) -> dict[str, Any]:
    windows = summary.get("windows") or {}
    data = windows.get("24h") if isinstance(windows, dict) else None
    return data if isinstance(data, dict) else {}


def _estimate_blocked_intents(
    summary: dict[str, Any],
    window: dict[str, Any],
    *,
    anomaly_threshold: int,
) -> int:
    """Prefer aggregator counter; fall back to recent_events + blocks floor."""
    if "blocked_intents" in window:
        try:
            return max(0, int(window.get("blocked_intents") or 0))
        except (TypeError, ValueError):
            pass
    recent = summary.get("recent_events") or []
    from_recent = sum(
        1
        for ev in recent
        if isinstance(ev, dict)
        and event_block_intent(ev, anomaly_threshold=anomaly_threshold)
    )
    blocks = int(window.get("blocks") or 0)
    critical = int(window.get("critical") or 0)
    # recent_events is a short tail — never under-report vs known blocks.
    return max(blocks, critical, from_recent)


def _split_top_rules(window: dict[str, Any], *, limit: int = 5) -> dict[str, list]:
    crs: list[dict[str, Any]] = []
    bastion: list[dict[str, Any]] = []
    for item in window.get("top_rules") or []:
        if not isinstance(item, dict):
            continue
        rid = str(item.get("rule_id") or "").strip()
        if not rid:
            continue
        row = {
            "rule_id": rid,
            "label": item.get("label") or rid,
            "count": int(item.get("count") or 0),
        }
        if rid.startswith("100096"):
            bastion.append(row)
        else:
            crs.append(row)
    return {
        "crs": crs[:limit],
        "bastion": bastion[:limit],
        "combined": (window.get("top_rules") or [])[:limit],
    }


def _attack_surfaces(window: dict[str, Any], *, limit: int = 5) -> list[dict[str, Any]]:
    families = window.get("rule_families") or []
    out: list[dict[str, Any]] = []
    for item in families[:limit]:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "id": item.get("family") or "autre",
                "label": item.get("label") or item.get("family") or "Autre",
                "count": int(item.get("count") or 0),
            }
        )
    return out


def _nginx_family_breakdown(
    db: Session,
    settings: Settings,
    window: dict[str, Any],
) -> list[dict[str, Any]]:
    """Best-effort Portal / Subdomain / Public split from top_hosts × App map."""
    portal = (getattr(settings, "portal_domain", None) or "").strip().lower()
    apps = db.query(App).all() if db is not None else []
    fqdn_mode: dict[str, str] = {}
    for app in apps:
        fqdn = (getattr(app, "public_fqdn", None) or "").strip().lower()
        if not fqdn:
            continue
        mode = (getattr(app, "access_mode", None) or "").strip().lower()
        if mode == "public_proxy":
            fqdn_mode[fqdn] = "public"
        else:
            fqdn_mode[fqdn] = "subdomain"

    counts = {"portal": 0, "subdomain": 0, "public": 0, "autre": 0}
    for item in window.get("top_hosts") or []:
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or "").strip().lower()
        n = int(item.get("count") or 0)
        if not host or host == "—":
            counts["autre"] += n
            continue
        if portal and (host == portal or host.endswith("." + portal)):
            counts["portal"] += n
        elif host in fqdn_mode:
            counts[fqdn_mode[host]] += n
        else:
            counts["autre"] += n

    labels = {
        "portal": "Portal",
        "subdomain": "Subdomain",
        "public": "Public",
        "autre": "Autre",
    }
    return [
        {"id": key, "label": labels[key], "count": counts[key]}
        for key in ("portal", "subdomain", "public", "autre")
        if counts[key] > 0
    ]


def _pack_status(profile: WafProfile, summary: dict[str, Any]) -> dict[str, Any]:
    total = len(PACK_CATALOG)
    on_n = detection_n = off_n = 0
    suggested_pending = 0
    for pack_id in PACK_CATALOG:
        mode = profile_pack_mode(profile, pack_id)
        if mode == PACK_MODE_ON:
            on_n += 1
        elif mode == PACK_MODE_DETECTION:
            detection_n += 1
        else:
            off_n += 1
            hints = _audit_hints_for_pack(pack_id, summary)
            if hints.get("signal"):
                suggested_pending += 1
    armed = on_n + detection_n
    return {
        "total": total,
        "on": on_n,
        "detection": detection_n,
        "off": off_n,
        "armed": armed,
        "armed_label": f"{armed}/{total}",
        "suggested_pending": suggested_pending,
        "armament_ratio": round(armed / total, 3) if total else 0.0,
        "blocking_ratio": round(on_n / total, 3) if total else 0.0,
        "detection_vs_on": {
            "detection": detection_n,
            "on": on_n,
            "ratio_detection": (
                round(detection_n / armed, 3) if armed else 0.0
            ),
        },
    }


def _triage_usage(db: Session) -> dict[str, Any]:
    """Sandbox probes + exclusions created this calendar month (UTC)."""
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    sandbox_n = 0
    exclusion_adds = 0
    if db is not None:
        sandbox_n = (
            db.query(func.count(AuditLog.id))
            .filter(
                AuditLog.action == "security.waf.sandbox_probe",
                AuditLog.created_at >= month_start,
            )
            .scalar()
            or 0
        )
        exclusion_adds = (
            db.query(func.count(AuditLog.id))
            .filter(
                AuditLog.action == "security.waf.exclusion_added",
                AuditLog.created_at >= month_start,
            )
            .scalar()
            or 0
        )
    active_exclusions = 0
    if db is not None:
        active_exclusions = (
            db.query(func.count(WafExclusion.id))
            .filter(WafExclusion.active.is_(True))
            .scalar()
            or 0
        )
    return {
        "sandbox_probes_month": int(sandbox_n),
        "exclusions_added_month": int(exclusion_adds),
        "exclusions_active": int(active_exclusions),
        "month_label": month_start.strftime("%Y-%m"),
    }


def build_waf_analytics_summary(
    db: Session,
    settings: Settings,
    profile: WafProfile | None = None,
    *,
    summary: dict[str, Any] | None = None,
    active: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile Bilan v1.1 KPIs without touching nginx."""
    from app.security.waf.service import get_active_profile

    profile = profile or get_active_profile(db)
    if profile is None:
        profile = WafProfile(name="__analytics__", mode="on", anomaly_threshold=5)

    summary = summary if summary is not None else read_audit_summary(settings)
    present = bool(summary.get("present"))
    window = _window_24h(summary) if present else {}
    threshold = int(getattr(profile, "anomaly_threshold", 5) or 5)

    inspected = int(window.get("inspected") or 0) if present else 0
    blocks = int(window.get("blocks") or 0) if present else 0
    blocked_intents = (
        _estimate_blocked_intents(summary, window, anomaly_threshold=threshold)
        if present
        else 0
    )
    # Never claim more blocks than intents.
    blocked_intents = max(blocked_intents, blocks)
    efficiency_ratio = (
        round(blocks / blocked_intents, 3) if blocked_intents else None
    )
    detection_gap = max(0, blocked_intents - blocks)

    packs = _pack_status(profile, summary if present else {"present": False})
    active = active if active is not None else read_nginx_waf_reality(settings=settings)
    portal_mode = portal_engine_mode(active) if active.get("verifiable") else None
    traffic_active = portal_mode in (PACK_MODE_ON, PACK_MODE_DETECTION, "on", "detection_only")
    telemetry = build_audit_health(
        settings, summary if present else None, traffic_active=bool(traffic_active)
    )
    age_sec = telemetry.get("mtime_age_seconds")
    last_write_ago_mins = (
        int(age_sec) // 60 if isinstance(age_sec, int) else None
    )

    top_rules = _split_top_rules(window)
    surfaces = _attack_surfaces(window)
    nginx_families = _nginx_family_breakdown(db, settings, window) if present else []
    triage = _triage_usage(db)

    return {
        "present": present,
        "window": "24h",
        "kpis": {
            "requests_evaluated": inspected,
            "requests_evaluated_display": _fmt_count(inspected),
            "requests_evaluated_label": "Événements d'audit (RelevantOnly)",
            "blocked_intents": blocked_intents,
            "blocked_intents_display": _fmt_count(blocked_intents),
            "blocked_intents_label": "Intentions de blocage",
            "blocks_executed": blocks,
            "blocks_executed_display": _fmt_count(blocks),
            "efficiency_ratio": efficiency_ratio,
            "efficiency_pct": (
                round(efficiency_ratio * 100, 1) if efficiency_ratio is not None else None
            ),
            "detection_gap": detection_gap,
            "anomaly_threshold": threshold,
        },
        "packs_status": packs,
        "telemetry": {
            "health_status": telemetry.get("level") or "red",
            "health_css": telemetry.get("css") or "badge-err",
            "health_label": telemetry.get("label") or "Audit indisponible",
            "health_detail": telemetry.get("detail") or "",
            "last_write_ago_mins": last_write_ago_mins,
            "size_bytes": int(telemetry.get("size_bytes") or 0),
            "stale": bool(telemetry.get("stale")),
            "oversized": bool(telemetry.get("oversized")),
            "summary_path": str(resolve_audit_summary_path(settings)),
        },
        "top_rules": top_rules,
        "attack_surfaces": surfaces,
        "nginx_families": nginx_families,
        "triage": triage,
        "portal_mode": portal_mode,
    }
