"""Dashboard metrics API — current-window operational and security KPIs."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.bastion.modsec_audit_aggregator import read_audit_summary
from app.database import get_db
from app.db.hot_store import hot_read
from app.models import App, AuditLog, SecurityBan, utcnow
from app.sso_settings import Settings, get_settings
from app.web.sessions_service import count_active_sessions_by_kind
from app.web.user_context import require_admin

# Router-level admin guard — metrics are operational/security sensitive.
router = APIRouter(
    prefix="/api",
    tags=["metrics"],
    dependencies=[Depends(require_admin)],
)

BLOCKED_WINDOW_HOURS = 24

# Auth / access / anti-abuse events that represent a blocked *attempt*
# (not admin config changes like activesync.device_blocked / ban.lifted).
_AUDIT_BLOCKED_FILTER = or_(
    AuditLog.action.like("%login_failed%"),
    AuditLog.action.like("access_denied%"),
    AuditLog.action.like("robotic.impersonate.blocked%"),
    AuditLog.action == "security.rate_limited",
    AuditLog.action == "access_request.rate_limited",
    AuditLog.action == "security.ban.applied",
    AuditLog.action == "security.hack_attempt.detected",
    AuditLog.action == "security.unknown_host_hammering.detected",
    AuditLog.action == "security.successful_login_hammering.detected",
)


def _count_audit_blocked_24h(db: Session) -> int | None:
    since = utcnow() - timedelta(hours=BLOCKED_WINDOW_HOURS)
    return hot_read(
        lambda: db.query(AuditLog)
        .filter(_AUDIT_BLOCKED_FILTER, AuditLog.created_at >= since)
        .count(),
        default=None,
        what="blocked attempts (24h audit)",
        db=db,
    )


def _waf_blocks_24h(settings: Settings) -> int | None:
    """ModSecurity blocks from the pre-aggregated WAF summary (never parse raw log)."""
    try:
        summary = read_audit_summary(settings)
    except Exception:
        return None
    if not summary.get("present"):
        return None
    if summary.get("log_available") is False and not (summary.get("windows") or {}):
        return 0
    windows = summary.get("windows") or {}
    data = windows.get("24h") or {}
    try:
        return int(data.get("blocks") or 0)
    except (TypeError, ValueError):
        return 0


def _active_ban_count(db: Session) -> int:
    now = utcnow()
    return (
        db.query(SecurityBan)
        .filter(
            SecurityBan.lifted_at.is_(None),
            or_(
                SecurityBan.permanent.is_(True),
                SecurityBan.expires_at.is_(None),
                SecurityBan.expires_at > now,
            ),
        )
        .count()
    )


def get_dashboard_metrics(db: Session, settings: Settings | None = None) -> dict:
    """KPIs for the admin dashboard.

    ``blocked_attempts`` is the sum of WAF ModSecurity blocks (24 h) and
    auth/access/security audit blocks (24 h). Active IP/username bans are
    exposed separately as current posture, not added into the 24 h total.
    """
    audit_blocked = _count_audit_blocked_24h(db)
    waf_blocks = _waf_blocks_24h(settings) if settings is not None else None
    try:
        active_bans = _active_ban_count(db)
    except Exception:
        active_bans = 0

    parts: list[int] = []
    if audit_blocked is not None:
        parts.append(int(audit_blocked))
    if waf_blocks is not None:
        parts.append(int(waf_blocks))
    blocked_total = sum(parts) if parts else None

    enabled_apps = db.query(App).filter_by(enabled=True).count()
    total_apps = db.query(App).count()
    sessions = count_active_sessions_by_kind(db)

    return {
        "active_sessions": sessions["all"],
        "active_sessions_user": sessions["user"],
        "active_sessions_app": sessions["app"],
        "blocked_attempts": blocked_total,
        "blocked_attempts_window_hours": BLOCKED_WINDOW_HOURS,
        "blocked_attempts_waf": 0 if waf_blocks is None else int(waf_blocks),
        "blocked_attempts_auth": 0 if audit_blocked is None else int(audit_blocked),
        "blocked_attempts_waf_available": waf_blocks is not None,
        "blocked_attempts_auth_available": audit_blocked is not None,
        "blocked_attempts_active_bans": int(active_bans),
        "enabled_apps": enabled_apps,
        "total_apps": total_apps,
    }


@router.get("/metrics")
def get_metrics(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    return get_dashboard_metrics(db, settings)
