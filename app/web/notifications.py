"""Admin notification center — actionable feed for the topbar bell."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.audit import derive_severity
from app.models import AuditLog, PendingHost, RealmConfig, utcnow

_DENIED_ACTIONS = (
    "access_denied_unknown_host",
    "access_denied_no_app",
    "access_denied_no_grant",
    "breakglass.login_denied_non_lan",
)

# Cap work: never full-scan audit_logs for a COUNT over 24h (SQLite can hang the UI).
_DENIED_FETCH_LIMIT = 50
_DENIED_DISPLAY_LIMIT = 5

SHORTCUTS: list[dict[str, str]] = [
    {
        "id": "logs",
        "label": "Logs",
        "href": "/admin/logs",
        "hint": "Audit métier & refus d'accès",
    },
    {
        "id": "domains",
        "label": "Domaines",
        "href": "/admin/pending-hosts",
        "hint": "Découverte d'hôtes inconnus",
    },
    {
        "id": "acme",
        "label": "ACME",
        "href": "/admin/acme",
        "hint": "Certificats Let's Encrypt",
    },
    {
        "id": "security",
        "label": "Sécurité",
        "href": "/admin/security",
        "hint": "SIEM, bans, break-glass",
    },
    {
        "id": "health",
        "label": "Santé",
        "href": "/admin/health",
        "hint": "État des services",
    },
    {
        "id": "apps",
        "label": "Apps",
        "href": "/admin/apps",
        "hint": "Catalogue & modes d'accès",
    },
    {
        "id": "realms",
        "label": "Realms",
        "href": "/admin/realms",
        "hint": "OIDC / Keycloak",
    },
]


def _fmt_time(dt) -> str | None:
    if not dt:
        return None
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def build_notification_feed(db: Session) -> dict[str, Any]:
    """Build badge count + actionable items for the notification panel."""
    items: list[dict[str, Any]] = []
    now = utcnow()
    since = now - timedelta(hours=24)

    pending_q = db.query(PendingHost).filter(PendingHost.status == "pending")
    pending_count = pending_q.count()
    if pending_count:
        latest = pending_q.order_by(PendingHost.last_seen_at.desc()).first()
        sample = ""
        if latest:
            sample = latest.hostname
            if latest.last_uri:
                sample = f"{latest.hostname}{latest.last_uri}"
        items.append(
            {
                "id": "pending-hosts",
                "severity": "warn",
                "category": "discovery",
                "title": (
                    f"{pending_count} domaine{'s' if pending_count > 1 else ''} "
                    "en attente"
                ),
                "body": (
                    f"Dernier vu : {sample}"
                    if sample
                    else "Hôtes inconnus à approuver ou rejeter"
                ),
                "href": "/admin/pending-hosts?status=pending",
                "time": _fmt_time(latest.last_seen_at) if latest else None,
                "count": pending_count,
            }
        )

    # One bounded query — avoid COUNT(*) over the whole 24h window (can lock the UI).
    denied_rows = (
        db.query(AuditLog)
        .filter(
            AuditLog.action.in_(_DENIED_ACTIONS),
            AuditLog.created_at >= since,
        )
        .order_by(AuditLog.created_at.desc())
        .limit(_DENIED_FETCH_LIMIT)
        .all()
    )
    denied_total = len(denied_rows)
    denied_capped = denied_total >= _DENIED_FETCH_LIMIT
    if denied_total:
        last = denied_rows[0]
        last_bits: list[str] = []
        if last.target:
            last_bits.append(str(last.target))
        uri = (last.details or {}).get("uri") if isinstance(last.details, dict) else None
        if uri:
            last_bits.append(str(uri))
        title_count = f"{denied_total}{'+' if denied_capped else ''}"
        items.append(
            {
                "id": "access-denied-summary",
                "severity": "error",
                "category": "security",
                "title": f"{title_count} accès refusés (24 h)",
                "body": (
                    "Dernier : " + " ".join(last_bits)
                    if last_bits
                    else "Voir les journaux d'accès refusés"
                ),
                "href": "/admin/logs?status=error",
                "time": _fmt_time(last.created_at),
                "count": denied_total,
            }
        )
        for row in denied_rows[:_DENIED_DISPLAY_LIMIT]:
            details = row.details if isinstance(row.details, dict) else {}
            uri = details.get("uri") or ""
            body_parts = [p for p in (row.target, uri) if p]
            items.append(
                {
                    "id": f"audit-{row.id}",
                    "severity": derive_severity(row.action),
                    "category": "security",
                    "title": row.action,
                    "body": " · ".join(str(p) for p in body_parts) or (row.actor or ""),
                    "href": f"/admin/logs?q={row.action}&status=error",
                    "time": _fmt_time(row.created_at),
                    "count": 1,
                }
            )

    bad_realms = (
        db.query(RealmConfig)
        .filter(
            RealmConfig.enabled == True,  # noqa: E712
            RealmConfig.last_test_status.isnot(None),
            RealmConfig.last_test_status != "ok",
        )
        .order_by(RealmConfig.slug.asc())
        .limit(5)
        .all()
    )
    for realm in bad_realms:
        items.append(
            {
                "id": f"realm-{realm.slug}",
                "severity": "warn",
                "category": "config",
                "title": f"Realm « {realm.slug} » — test OIDC KO",
                "body": f"Statut : {realm.last_test_status}",
                "href": "/admin/realms",
                "time": None,
                "count": 1,
            }
        )

    badge = pending_count + (1 if denied_total else 0) + len(bad_realms)

    return {
        "count": int(badge),
        "items": items,
        "shortcuts": SHORTCUTS,
        "generated_at": _fmt_time(now),
    }
