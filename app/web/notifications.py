"""Admin notification center — actionable feed for the topbar bell."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.audit import derive_severity, log_action
from app.models import (
    AdminNotificationDismissal,
    AuditLog,
    PendingHost,
    PendingUser,
    RealmConfig,
    utcnow,
)

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
        "id": "new-users",
        "label": "Nouveaux users",
        "href": "/admin/pending-users",
        "hint": "Premières connexions SSO",
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


def _dismissal_map(db: Session, user_email: str | None) -> dict[str, str]:
    if not user_email:
        return {}
    rows = (
        db.query(AdminNotificationDismissal)
        .filter(AdminNotificationDismissal.user_email == user_email.strip().lower())
        .all()
    )
    return {r.item_id: (r.fingerprint or "") for r in rows}


def _is_dismissed(item: dict[str, Any], dismissed: dict[str, str]) -> bool:
    item_id = str(item.get("id") or "")
    if not item_id or item_id not in dismissed:
        return False
    return dismissed[item_id] == str(item.get("fingerprint") or "")


def dismiss_notification(
    db: Session,
    *,
    user_email: str,
    item_id: str,
    fingerprint: str,
    actor: str,
) -> None:
    email = (user_email or "").strip().lower()
    iid = (item_id or "").strip()
    if not email or not iid:
        raise ValueError("item_id / user requis")
    fp = (fingerprint or "").strip()
    row = (
        db.query(AdminNotificationDismissal)
        .filter_by(user_email=email, item_id=iid)
        .first()
    )
    if row is None:
        row = AdminNotificationDismissal(
            user_email=email,
            item_id=iid,
            fingerprint=fp,
            dismissed_at=utcnow(),
        )
        db.add(row)
    else:
        row.fingerprint = fp
        row.dismissed_at = utcnow()
    db.commit()
    log_action(
        db,
        actor=actor,
        action="notification.dismissed",
        target=iid,
        details={"fingerprint": fp[:200]},
    )


def dismiss_all_notifications(
    db: Session,
    *,
    user_email: str,
    items: list[dict[str, Any]],
    actor: str,
) -> int:
    email = (user_email or "").strip().lower()
    if not email:
        return 0
    n = 0
    for it in items:
        iid = str(it.get("id") or "").strip()
        if not iid:
            continue
        fp = str(it.get("fingerprint") or "")
        row = (
            db.query(AdminNotificationDismissal)
            .filter_by(user_email=email, item_id=iid)
            .first()
        )
        if row is None:
            db.add(
                AdminNotificationDismissal(
                    user_email=email,
                    item_id=iid,
                    fingerprint=fp,
                    dismissed_at=utcnow(),
                )
            )
        else:
            row.fingerprint = fp
            row.dismissed_at = utcnow()
        n += 1
    db.commit()
    if n:
        log_action(
            db,
            actor=actor,
            action="notification.dismissed_all",
            target="notifications",
            details={"count": n},
        )
    return n


def build_notification_feed(
    db: Session,
    *,
    user_email: str | None = None,
) -> dict[str, Any]:
    """Build badge count + actionable items for the notification panel."""
    items: list[dict[str, Any]] = []
    now = utcnow()
    since = now - timedelta(hours=24)

    from app.bastion.pending_host_service import is_infra_discovery_probe

    pending_q = db.query(PendingHost).filter(PendingHost.status == "pending")
    pending_rows = [
        r for r in pending_q.order_by(PendingHost.last_seen_at.desc()).limit(200).all()
        if not is_infra_discovery_probe(r.hostname)
    ]
    pending_count = len(pending_rows)
    if pending_count:
        latest = pending_rows[0]
        sample = ""
        fp_bits = [str(pending_count)]
        if latest:
            sample = latest.hostname
            if latest.last_uri:
                sample = f"{latest.hostname}{latest.last_uri}"
            fp_bits.append(latest.hostname or "")
            fp_bits.append(str(int(latest.hit_count or 0)))
            if latest.last_seen_at:
                fp_bits.append(latest.last_seen_at.isoformat())
        items.append(
            {
                "id": "pending-hosts",
                "fingerprint": "|".join(fp_bits),
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
                "counts_for_badge": True,
                "dismissible": True,
            }
        )

    from app.web.pending_user_service import discover_recent_first_logins

    try:
        if discover_recent_first_logins(db):
            db.commit()
    except Exception:
        db.rollback()

    pending_user_rows = (
        db.query(PendingUser)
        .filter(PendingUser.status == "pending")
        .order_by(PendingUser.last_seen_at.desc())
        .limit(200)
        .all()
    )
    pending_user_count = len(pending_user_rows)
    if pending_user_count:
        latest_u = pending_user_rows[0]
        fp_u = [
            str(pending_user_count),
            latest_u.user_email or "",
            str(int(latest_u.hit_count or 0)),
        ]
        if latest_u.last_seen_at:
            fp_u.append(latest_u.last_seen_at.isoformat())
        items.append(
            {
                "id": "pending-users",
                "fingerprint": "|".join(fp_u),
                "severity": "info",
                "category": "identity",
                "title": (
                    f"{pending_user_count} nouvelle"
                    f"{'s' if pending_user_count > 1 else ''} connexion"
                    f"{'s' if pending_user_count > 1 else ''}"
                ),
                "body": (
                    f"Dernier : {latest_u.user_email}"
                    if latest_u.user_email
                    else "Utilisateurs SSO à valider"
                ),
                "href": "/admin/pending-users?status=pending",
                "time": _fmt_time(latest_u.last_seen_at) if latest_u else None,
                "count": pending_user_count,
                "counts_for_badge": True,
                "dismissible": True,
            }
        )

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
                "fingerprint": f"{last.id}|{_fmt_time(last.created_at)}|{denied_total}",
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
                "counts_for_badge": True,
                "dismissible": True,
            }
        )
        for row in denied_rows[:_DENIED_DISPLAY_LIMIT]:
            details = row.details if isinstance(row.details, dict) else {}
            uri = details.get("uri") or ""
            body_parts = [p for p in (row.target, uri) if p]
            items.append(
                {
                    "id": f"audit-{row.id}",
                    "fingerprint": str(row.id),
                    "severity": derive_severity(row.action),
                    "category": "security",
                    "title": row.action,
                    "body": " · ".join(str(p) for p in body_parts) or (row.actor or ""),
                    "href": f"/admin/logs?q={row.action}&status=error",
                    "time": _fmt_time(row.created_at),
                    "count": 1,
                    "counts_for_badge": False,
                    "dismissible": True,
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
                "fingerprint": f"{realm.slug}|{realm.last_test_status}",
                "severity": "warn",
                "category": "config",
                "title": f"Realm « {realm.slug} » — test OIDC KO",
                "body": f"Statut : {realm.last_test_status}",
                "href": "/admin/realms",
                "time": None,
                "count": 1,
                "counts_for_badge": True,
                "dismissible": True,
            }
        )

    dismissed = _dismissal_map(db, user_email)
    visible = [i for i in items if not _is_dismissed(i, dismissed)]
    badge = sum(1 for i in visible if i.get("counts_for_badge"))

    return {
        "count": int(badge),
        "items": visible,
        "shortcuts": SHORTCUTS,
        "generated_at": _fmt_time(now),
    }
