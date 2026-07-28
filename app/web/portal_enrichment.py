"""Portal UI enrichment — status badges, recent sessions, filter keys."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.access_modes import normalize_access_mode
from app.bastion.bastion_fields import normalize_auth_mode, vault_enabled_for_app
from app.models import App, AuditLog
from app.web.sessions_service import (
    identity_match_keys,
    list_active_app_sessions_for_identity,
)
from app.web.user_context import UserContext

# Chip filters for /apps (Bastion catalogue is web-first; no fake SSH/RDP).
PORTAL_FILTERS: tuple[tuple[str, str], ...] = (
    ("all", "Tous"),
    ("web", "Web"),
    ("proxy", "Proxy"),
    ("vault", "Vault"),
)


def _probe_badge(app: App) -> dict[str, str] | None:
    status = (app.last_probe_status or "").strip().lower()
    if status in ("ok", "healthy", "up"):
        return {"key": "operational", "label": "Opérationnel", "class": "badge-ok"}
    if status in ("warn", "warning", "degraded"):
        return {"key": "degraded", "label": "Dégradé", "class": "badge-warn"}
    if status in ("error", "down", "fail", "failed", "critical"):
        return {"key": "down", "label": "Indisponible", "class": "badge-err"}
    return None


def _protection_badge(app: App) -> dict[str, str] | None:
    """SSO / vault-backed apps are « Protégé » — real signal, not marketing fluff."""
    auth = normalize_auth_mode(getattr(app, "auth_mode", None))
    if vault_enabled_for_app(auth, getattr(app, "robotic_driver", None)):
        return {"key": "protected", "label": "Protégé", "class": "badge-info"}
    mode = normalize_access_mode(app.access_mode)
    if mode in ("sso_gate", "subdomain_proxy", "legacy_path_proxy"):
        return {"key": "protected", "label": "Protégé", "class": "badge-info"}
    return None


def protocol_filter_key(app: App) -> str:
    mode = normalize_access_mode(app.access_mode)
    auth = normalize_auth_mode(getattr(app, "auth_mode", None))
    if vault_enabled_for_app(auth, getattr(app, "robotic_driver", None)):
        return "vault"
    if mode in ("subdomain_proxy", "legacy_path_proxy", "public_proxy"):
        return "proxy"
    return "web"


def enrich_tile(app: App, tile: dict[str, Any]) -> dict[str, Any]:
    badges: list[dict[str, str]] = []
    prot = _protection_badge(app)
    if prot:
        badges.append(prot)
    probe = _probe_badge(app)
    if probe:
        badges.append(probe)
    tile["status_badges"] = badges
    tile["protocol_filter"] = protocol_filter_key(app)
    tile["auth_mode"] = normalize_auth_mode(getattr(app, "auth_mode", None))
    return tile


def _fmt_relative(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    try:
        from app.models import utcnow

        now = utcnow()
        if dt.tzinfo is None and now.tzinfo is not None:
            from datetime import timezone

            dt = dt.replace(tzinfo=timezone.utc)
        delta = now - dt
        secs = int(delta.total_seconds())
        if secs < 60:
            return "à l'instant"
        if secs < 3600:
            return f"il y a {secs // 60} min"
        if secs < 86400:
            return f"il y a {secs // 3600} h"
        return f"il y a {secs // 86400} j"
    except Exception:
        return dt.isoformat() if hasattr(dt, "isoformat") else "—"


def recent_sessions_for_user(
    db: Session,
    user: UserContext,
    *,
    apps_by_slug: dict[str, dict[str, Any]] | None = None,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """
    Recent app sessions for the portal sidebar.
    Primary: ActiveSession kind=app; fallback: recent app_launch audit rows.
    """
    emails, usernames = identity_match_keys(
        email=user.email, username=user.username
    )
    apps_by_slug = apps_by_slug or {}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    rows = list_active_app_sessions_for_identity(
        db, emails=emails, usernames=usernames
    )
    for row in rows:
        slug = (row.target or "").strip()
        if not slug or slug in seen:
            continue
        seen.add(slug)
        tile = apps_by_slug.get(slug)
        details = row.details if isinstance(row.details, dict) else {}
        label = (
            (details.get("app_label") if details else None)
            or (tile.get("label") if tile else None)
            or slug
        )
        out.append(
            {
                "slug": slug,
                "label": label,
                "protocol": (row.protocol or "WEB").upper(),
                "last_seen_label": _fmt_relative(row.last_seen_at),
                "launch_url": tile.get("launch_url") if tile else None,
                "can_launch": bool(tile and tile.get("can_launch")),
                "app_id": tile.get("id") if tile else None,
                "source": "session",
            }
        )
        if len(out) >= limit:
            return out

    # Fallback: audit app_launch for this actor
    actors = {a for a in (user.email, user.username) if a}
    if actors and len(out) < limit:
        audits = (
            db.query(AuditLog)
            .filter(
                AuditLog.action == "app_launch",
                AuditLog.actor.in_(actors),
            )
            .order_by(AuditLog.id.desc())
            .limit(limit * 2)
            .all()
        )
        for entry in audits:
            slug = (entry.target or "").strip()
            if not slug or slug in seen:
                continue
            seen.add(slug)
            tile = apps_by_slug.get(slug)
            out.append(
                {
                    "slug": slug,
                    "label": tile.get("label") if tile else slug,
                    "protocol": "WEB",
                    "last_seen_label": _fmt_relative(entry.created_at),
                    "launch_url": tile.get("launch_url") if tile else None,
                    "can_launch": bool(tile and tile.get("can_launch")),
                    "app_id": tile.get("id") if tile else None,
                    "source": "audit",
                }
            )
            if len(out) >= limit:
                break

    return out
