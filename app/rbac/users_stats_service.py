"""RBAC users page — Keycloak live stats, anomalies, avatar helpers."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models import AccessGrant, ActiveSession, AuditLog, RBACGroup, RealmConfig, utcnow
from app.rbac.keycloak_admin import count_keycloak_users
from app.sso_settings import Settings


def _dt_aware(value):
    """SQLite often returns naive datetimes; utcnow() is aware — normalize for compares."""
    if value is None:
        return None
    if getattr(value, "tzinfo", None) is None:
        from datetime import timezone

        return value.replace(tzinfo=timezone.utc)
    return value

# Short in-process cache for Keycloak counts (seconds).
_STATS_TTL = 60.0
_stats_cache: dict[str, tuple[float, dict[str, Any]]] = {}

# Deterministic avatar backgrounds from existing semantic tokens (no new palette).
AVATAR_COLORS: tuple[str, ...] = (
    "var(--ok)",
    "var(--info)",
    "var(--warn)",
    "var(--err)",
    "var(--purple)",
    "var(--accent)",
)


def avatar_color_for(name: str) -> str:
    digest = hashlib.sha256((name or "?").encode("utf-8")).hexdigest()
    return AVATAR_COLORS[int(digest[:8], 16) % len(AVATAR_COLORS)]


def avatar_initials(name: str) -> str:
    raw = (name or "?").strip()
    if "@" in raw:
        raw = raw.split("@", 1)[0]
    parts = [p for p in raw.replace("_", ".").replace("-", ".").split(".") if p]
    if len(parts) >= 2:
        return (parts[0][0] + parts[1][0]).upper()
    if parts:
        token = parts[0]
        return (token[:2] if len(token) >= 2 else token[:1]).upper()
    return "?"


@dataclass
class UserStats:
    total: int | None = None
    active: int | None = None
    privileged: int | None = None
    suspended: int | None = None
    error: str | None = None
    privileged_new_7d: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "active": self.active,
            "privileged": self.privileged,
            "suspended": self.suspended,
            "error": self.error,
            "privileged_new_7d": self.privileged_new_7d,
        }


def count_privileged_subjects(db: Session) -> tuple[int, int]:
    """
    Privileged = unique subjects with system_role AccessGrant
    (portal_admin / portal_auditor), direct user or via group (count subjects
    as keycloak_user_id or rbac_group_id respectively — group counts as 1
    privileged bucket for the card, matching « grants + admin groups »).

    Returns (total_privileged_buckets, grants_created_last_7d).
    """
    grants = (
        db.query(AccessGrant)
        .filter(AccessGrant.resource_type == "system_role")
        .all()
    )
    subjects: set[str] = set()
    new_7d = 0
    cutoff = utcnow() - timedelta(days=7)
    for g in grants:
        if g.subject_type == "user" and g.keycloak_user_id:
            subjects.add(f"u:{g.keycloak_user_id}")
        elif g.subject_type == "group" and g.rbac_group_id:
            subjects.add(f"g:{g.rbac_group_id}")
        if _dt_aware(g.granted_at) and _dt_aware(g.granted_at) >= cutoff:
            new_7d += 1
    return len(subjects), new_7d


async def fetch_user_directory_stats(
    db: Session,
    realm: RealmConfig | None,
    settings: Settings,
) -> UserStats:
    """Live Keycloak counts + privileged grants. Cached 60s per realm."""
    privileged, new_7d = count_privileged_subjects(db)
    stats = UserStats(privileged=privileged, privileged_new_7d=new_7d)

    if realm is None:
        stats.error = "Aucun realm avec sync activée"
        return stats

    cache_key = f"realm:{realm.id}"
    now = time.monotonic()
    cached = _stats_cache.get(cache_key)
    if cached and cached[0] > now:
        data = cached[1]
        stats.total = data.get("total")
        stats.active = data.get("active")
        stats.suspended = data.get("suspended")
        stats.error = data.get("error")
        return stats

    try:
        total = await count_keycloak_users(realm, settings)
        active = await count_keycloak_users(realm, settings, enabled=True)
        suspended = await count_keycloak_users(realm, settings, enabled=False)
        stats.total = total
        stats.active = active
        stats.suspended = suspended
        _stats_cache[cache_key] = (
            now + _STATS_TTL,
            {
                "total": total,
                "active": active,
                "suspended": suspended,
                "error": None,
            },
        )
    except ValueError as exc:
        stats.error = str(exc)
        _stats_cache[cache_key] = (
            now + min(15.0, _STATS_TTL),
            {"total": None, "active": None, "suspended": None, "error": str(exc)},
        )
    except Exception:
        stats.error = "Keycloak indisponible pour le comptage utilisateurs"
        _stats_cache[cache_key] = (
            now + 15.0,
            {
                "total": None,
                "active": None,
                "suspended": None,
                "error": stats.error,
            },
        )
    return stats


def clear_user_stats_cache() -> None:
    _stats_cache.clear()


def connection_anomalies(db: Session, *, limit: int = 12) -> list[dict[str, Any]]:
    """
    V1 anomalies panel from existing audit_logs:
    - session_hijack_suspected → CRITIQUE
    - breakglass.login_failed (recent) → ALERTE
    """
    rows = (
        db.query(AuditLog)
        .filter(
            AuditLog.action.in_(
                ("session_hijack_suspected", "breakglass.login_failed")
            )
        )
        .order_by(desc(AuditLog.id))
        .limit(limit)
        .all()
    )
    out: list[dict[str, Any]] = []
    for row in rows:
        severity = (
            "CRITIQUE" if row.action == "session_hijack_suspected" else "ALERTE"
        )
        out.append(
            {
                "action": row.action,
                "actor": row.actor,
                "target": row.target,
                "ip": row.ip_address,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "severity": severity,
                "details": row.details or {},
            }
        )
    return out


def group_distribution(db: Session) -> dict[str, Any]:
    """Membership snapshot for the Users page widget.

    Rows are sorted by ``member_count`` desc (then name). Percentages are the
    share of total memberships; ``bar_percent`` is relative to the largest
    group so the top bar fills the track.
    """
    groups = db.query(RBACGroup).order_by(RBACGroup.name).all()
    total = sum(int(g.member_count or 0) for g in groups)
    rows: list[dict[str, Any]] = []
    for g in groups:
        count = int(g.member_count or 0)
        share = int(round(100.0 * count / total)) if total else 0
        rows.append(
            {
                "id": g.id,
                "name": g.name,
                "member_count": count,
                "percent": share,
                "bar_percent": 0,
            }
        )
    rows.sort(key=lambda r: (-int(r["member_count"]), str(r["name"]).casefold()))
    max_count = max((int(r["member_count"]) for r in rows), default=0)
    for r in rows:
        r["bar_percent"] = (
            int(round(100.0 * int(r["member_count"]) / max_count)) if max_count else 0
        )
    with_members = sum(1 for r in rows if int(r["member_count"]) > 0)
    return {
        "rows": rows,
        "total_groups": len(rows),
        "with_members": with_members,
        "empty_groups": len(rows) - with_members,
        "total_memberships": total,
    }


def last_seen_for_users(
    db: Session, granted_users: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """
    Best-effort last activity from ActiveSession (email/username) and AuditLog.
    ActiveSession has no keycloak_user_id — match on display email / username.
    """
    out: dict[str, dict[str, Any]] = {}
    for u in granted_users:
        uid = u.get("keycloak_user_id")
        if not uid:
            continue
        display = (u.get("display") or "").strip()
        candidates = {uid}
        if display:
            candidates.add(display)
            if "@" in display:
                candidates.add(display.split("@", 1)[0])

        session_row = (
            db.query(ActiveSession)
            .filter(
                (ActiveSession.user_email.in_(candidates))
                | (ActiveSession.username.in_(candidates))
            )
            .order_by(desc(ActiveSession.last_seen_at))
            .first()
        )
        if session_row:
            out[uid] = {
                "last_seen_at": (
                    session_row.last_seen_at.isoformat()
                    if session_row.last_seen_at
                    else None
                ),
                "ip": session_row.source_ip,
            }
            continue

        audit = (
            db.query(AuditLog)
            .filter(AuditLog.actor.in_(candidates))
            .order_by(desc(AuditLog.id))
            .first()
        )
        if audit:
            out[uid] = {
                "last_seen_at": audit.created_at.isoformat() if audit.created_at else None,
                "ip": audit.ip_address,
            }
    return out


def enrich_granted_users(
    db: Session,
    granted_users: list[dict[str, Any]],
    *,
    group_filter: str | None = None,
    status_filter: str | None = None,
) -> list[dict[str, Any]]:
    """
    Enrich list_users_with_direct_grants rows with avatar + last_seen.
    status_filter / group_filter are best-effort (no Keycloak enabled flag on
    grant-only rows — status stays 'known' / privileged).
    """
    last_map = last_seen_for_users(db, granted_users)
    out: list[dict[str, Any]] = []
    for u in granted_users:
        display = u.get("display") or u.get("keycloak_user_id") or "?"
        uid = u.get("keycloak_user_id")
        last = last_map.get(uid or "", {})
        entry = {
            **u,
            "initials": avatar_initials(display),
            "avatar_color": avatar_color_for(display),
            "last_seen_at": last.get("last_seen_at"),
            "last_ip": last.get("ip"),
            "status": "privileged" if u.get("has_portal_admin") else "actif",
        }
        if status_filter and status_filter != "tous":
            if status_filter == "privilegies" and not u.get("has_portal_admin"):
                continue
            if status_filter == "inactifs":
                # Grant-only list has no Keycloak enabled=false — skip filter
                continue
        if group_filter:
            # V1: no group membership on grant rows — keep all
            pass
        out.append(entry)
    return out
