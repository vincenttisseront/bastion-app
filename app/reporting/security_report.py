"""Aggregate Bastion security telemetry into a compliance report payload."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from sqlalchemy.orm import Session

from app.sso_settings import Settings

logger = logging.getLogger(__name__)

PeriodName = Literal["weekly", "monthly"]


def period_window(
    period: PeriodName,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """UTC window for ``weekly`` (7d) or ``monthly`` (calendar month to date)."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    end = now
    if period == "weekly":
        start = end - timedelta(days=7)
        label = f"Hebdomadaire ({start.date().isoformat()} → {end.date().isoformat()})"
    else:
        start = end.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        label = f"Mensuel ({start.strftime('%Y-%m')})"
    return {
        "name": period,
        "label": label,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "start_dt": start,
        "end_dt": end,
    }


def _score_compliance(
    *,
    runtime_ok: bool,
    telemetry_present: bool,
    packs_armed_ratio: float,
    portal_blocking: bool,
    mfa_pct: float,
    mfa_enforcement: bool,
    mtls_ca_present: bool,
    allowlist_ips: int,
) -> tuple[int, list[str]]:
    """Weighted 0–100 score; notes explain the rubric in the PDF."""
    notes: list[str] = [
        "Pondération : runtime 25 · télémétrie WAF 15 · packs/mode 15 · "
        "MFA 20 · CA mTLS 15 · allowlist 10.",
    ]
    score = 0

    if runtime_ok:
        score += 25
        notes.append("+25 runtime hardened (non-root, read-only, no_new_privs).")
    else:
        notes.append("+0 runtime loose — isoler le conteneur app (uid, read_only, nnp).")

    if telemetry_present:
        score += 15
        notes.append("+15 télémétrie RelevantOnly présente.")
    else:
        notes.append("+0 télémétrie audit absente ou illisible.")

    pack_pts = int(round(15 * max(0.0, min(1.0, packs_armed_ratio))))
    if portal_blocking:
        pack_pts = min(15, pack_pts + 3)
    score += pack_pts
    notes.append(
        f"+{pack_pts} packs armés (ratio={packs_armed_ratio:.0%})"
        + (" + mode portail bloquant." if portal_blocking else ".")
    )

    if mfa_enforcement:
        mfa_pts = int(round(20 * max(0.0, min(1.0, mfa_pct / 100.0))))
    else:
        # Soft credit when enforcement is off but some admins enrolled.
        mfa_pts = 10 + int(round(10 * max(0.0, min(1.0, mfa_pct / 100.0))))
    score += mfa_pts
    notes.append(
        f"+{mfa_pts} MFA (enrôlement {mfa_pct:.0f}%, "
        f"enforcement={'on' if mfa_enforcement else 'off'})."
    )

    if mtls_ca_present:
        score += 15
        notes.append("+15 CA mTLS interne présente.")
    else:
        notes.append("+0 CA mTLS absente.")

    if allowlist_ips > 0:
        score += 10
        notes.append(f"+10 allowlist configurée ({allowlist_ips} IP).")
    else:
        notes.append("+0 allowlist vide (pas de points).")

    return max(0, min(100, score)), notes


def _mfa_stats(db: Session, settings: Settings) -> dict[str, Any]:
    from app.auth.mfa_gate import grace_days_left
    from app.models import AdminMfaCredential

    rows = db.query(AdminMfaCredential).all() if db is not None else []
    enrolled = sum(
        1 for r in rows if bool(r.totp_enabled) or bool(r.webauthn_enabled)
    )
    total = len(rows)
    # Denominator: at least enrolled; if empty table, 0%.
    denom = total if total > 0 else 0
    pct = round(100.0 * enrolled / denom, 1) if denom else 0.0
    enforcement = bool(getattr(settings, "mfa_enforcement_required", False))
    return {
        "mfa_enrolled": enrolled,
        "mfa_total": denom,
        "mfa_enrollment_pct": pct,
        "mfa_enforcement": "required" if enforcement else "off",
        "mfa_grace_days_left": grace_days_left(settings),
    }


def _mtls_stats(db: Session, settings: Settings) -> dict[str, Any]:
    from app.acme.mtls_client_service import mtls_dashboard_payload

    payload = mtls_dashboard_payload(db, settings)
    ca = payload.get("ca")
    counts = payload.get("counts") or {}
    clients = [
        c
        for c in (payload.get("clients") or [])
        if (c.get("status") or "") == "active"
    ]
    return {
        "mtls_ca": {
            "present": ca is not None,
            "fingerprint_sha256": (ca or {}).get("fingerprint_sha256"),
            "not_after": (ca or {}).get("not_after"),
            "subject": (ca or {}).get("subject"),
        },
        "mtls_active": int(counts.get("active") or 0),
        "mtls_total": int(counts.get("total") or 0),
        "mtls_clients": clients,
    }


def _auto_bans_in_period(db: Session, start: datetime, end: datetime) -> int:
    from app.models import SecurityBan
    from app.security.banning.engine import RULE_NGINX_LIMIT_REQ

    if db is None:
        return 0
    return (
        db.query(SecurityBan)
        .filter(
            SecurityBan.target_type == "ip",
            SecurityBan.rule_type == RULE_NGINX_LIMIT_REQ,
            SecurityBan.banned_at >= start,
            SecurityBan.banned_at <= end,
        )
        .count()
    )


def build_security_report(
    db: Session,
    settings: Settings,
    *,
    period: PeriodName = "monthly",
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the structured payload consumed by ``pdf_engine``."""
    from app.bastion.waf_analytics import build_waf_analytics_summary
    from app.security.runtime_check import check_runtime_hardening

    window = period_window(period, now=now)
    analytics = build_waf_analytics_summary(db, settings)
    kpis = analytics.get("kpis") or {}
    network = analytics.get("network") or {}
    packs = analytics.get("packs_status") or {}
    top = analytics.get("top_rules") or {}
    combined_rules = list(top.get("combined") or [])[:5]
    if not combined_rules:
        combined_rules = (list(top.get("crs") or []) + list(top.get("bastion") or []))[
            :5
        ]

    runtime = check_runtime_hardening()
    mfa = _mfa_stats(db, settings)
    mtls = _mtls_stats(db, settings)

    portal_mode = (analytics.get("portal_mode") or "") or ""
    portal_blocking = portal_mode in ("on", "On")
    packs_ratio = float(packs.get("armament_ratio") or 0.0)
    allowlist_ips = int(network.get("allowlist_ips") or 0)

    score, score_notes = _score_compliance(
        runtime_ok=bool(runtime.get("ok")),
        telemetry_present=bool(analytics.get("present")),
        packs_armed_ratio=packs_ratio,
        portal_blocking=portal_blocking,
        mfa_pct=float(mfa.get("mfa_enrollment_pct") or 0.0),
        mfa_enforcement=mfa.get("mfa_enforcement") == "required",
        mtls_ca_present=bool((mtls.get("mtls_ca") or {}).get("present")),
        allowlist_ips=allowlist_ips,
    )

    auto_in_period = _auto_bans_in_period(
        db, window["start_dt"], window["end_dt"]
    )

    generated = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return {
        "period": {
            "name": window["name"],
            "label": window["label"],
            "start": window["start"],
            "end": window["end"],
        },
        "meta": {
            "generated_at": generated.isoformat(),
            "portal_domain": getattr(settings, "portal_domain", None)
            or "portal.example.com",
        },
        "executive": {
            "compliance_score": score,
            "score_notes": score_notes,
            "blocked_intents": int(kpis.get("blocked_intents") or 0),
            "blocks_executed": int(kpis.get("blocks_executed") or 0),
            "rate_limit_429_24h": int(network.get("rate_limit_429_24h") or 0),
            "auto_bans_active": int(network.get("auto_bans_active") or 0),
            "runtime_status": runtime.get("runtime_status") or "loose",
            "is_root": runtime.get("is_root"),
            "read_only_fs": runtime.get("read_only_fs"),
            "no_new_privileges": runtime.get("no_new_privileges"),
        },
        "perimeter": {
            "requests_evaluated": int(kpis.get("requests_evaluated") or 0),
            "portal_mode": portal_mode or None,
            "allowlist_ips": allowlist_ips,
            "promoted_deny_count": int(network.get("promoted_deny_count") or 0),
            "auto_bans_in_period": auto_in_period,
            "top_rules": combined_rules,
        },
        "identity": {
            **mfa,
            **mtls,
        },
    }


def reports_dir(settings: Settings) -> Path:
    root = Path(settings.portal_data_dir or "/var/lib/sso-portal")
    return root / "reports"


def store_report_pdf(
    settings: Settings,
    pdf_bytes: bytes,
    *,
    period: PeriodName,
    generated_at: datetime | None = None,
) -> Path:
    """Write PDF under ``{PORTAL_DATA_DIR}/reports/``; return path."""
    generated_at = generated_at or datetime.now(timezone.utc)
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)
    dest = reports_dir(settings)
    dest.mkdir(parents=True, exist_ok=True)
    stamp = generated_at.strftime("%Y%m%d-%H%M%S")
    path = dest / f"bastion-compliance-{period}-{stamp}.pdf"
    path.write_bytes(pdf_bytes)
    return path


def generate_and_store_report(
    db: Session,
    settings: Settings,
    *,
    period: PeriodName = "monthly",
    actor: str = "scheduler",
    store: bool = True,
    audit: bool = True,
) -> tuple[dict[str, Any], bytes, Path | None]:
    """Aggregate → PDF → optional disk + audit ``security.report.generated``."""
    from app.audit import log_action
    from app.reporting.pdf_engine import render_security_compliance_pdf

    payload = build_security_report(db, settings, period=period)
    pdf = render_security_compliance_pdf(payload)
    path: Path | None = None
    if store:
        try:
            path = store_report_pdf(settings, pdf, period=period)
        except OSError:
            logger.exception("failed to store compliance PDF under reports/")
            path = None
    if audit:
        log_action(
            db,
            actor=actor,
            action="security.report.generated",
            target=str(path) if path else f"period:{period}",
            details={
                "period": period,
                "score": (payload.get("executive") or {}).get("compliance_score"),
                "bytes": len(pdf),
                "stored": path is not None,
            },
        )
    return payload, pdf, path


def monthly_compliance_report_job(*, settings: Settings) -> None:
    """APScheduler entry: 1st of month compliance PDF (audit + disk)."""
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        _, _, path = generate_and_store_report(
            db,
            settings,
            period="monthly",
            actor="scheduler",
            store=True,
            audit=True,
        )
        logger.info(
            "Monthly compliance report generated%s",
            f" path={path}" if path else "",
        )
    except Exception:
        logger.exception("monthly compliance report job failed")
    finally:
        db.close()
