"""Shared pending-queue counters for sidebar, dashboard, and notifications.

Single source of truth for "éléments en attente" — no duplicated counting logic.
Only surfaces categories backed by real DB rows (never invents zero placeholders).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.bastion.pending_host_service import is_infra_discovery_probe
from app.models import ActiveSyncDevice, BastionAccount, PendingHost, PendingUser, utcnow
from app.rbac.access_request_service import count_pending_access_requests


def count_pending_users(db: Session) -> int:
    return (
        db.query(PendingUser).filter(PendingUser.status == "pending").count()
    )


def count_pending_hosts(db: Session) -> int:
    """Pending unknown Hosts, excluding Ansible discovery-probe noise."""
    rows = (
        db.query(PendingHost.hostname)
        .filter(PendingHost.status == "pending")
        .all()
    )
    return sum(1 for (hostname,) in rows if not is_infra_discovery_probe(hostname))


def count_pending_devices(db: Session) -> int:
    """ActiveSync devices awaiting admin approve / block."""
    return (
        db.query(ActiveSyncDevice)
        .filter(ActiveSyncDevice.status == "pending")
        .count()
    )


def count_pending_bastion_accounts(db: Session) -> int:
    """Bastion-created accounts still pending Keycloak or with provisioning failures."""
    return (
        db.query(BastionAccount)
        .filter(BastionAccount.status.in_(("pending", "partial_failure")))
        .count()
    )


def pending_nav_counts(db: Session) -> dict[str, int]:
    """Counts injected into every admin chrome context (sidebar badges)."""
    users = count_pending_users(db)
    hosts = count_pending_hosts(db)
    devices = count_pending_devices(db)
    access = count_pending_access_requests(db)
    accounts = count_pending_bastion_accounts(db)
    return {
        "pending_users": users,
        "pending_hosts": hosts,
        "pending_devices": devices,
        "access_requests": access,
        "bastion_accounts": accounts,
        "total": users + hosts + devices + access + accounts,
    }


def _plural(n: int, singular: str, plural: str | None = None) -> str:
    if n == 1:
        return singular
    return plural or (singular + "s")


def _fmt_relative(dt) -> str | None:
    if not dt:
        return None
    now = utcnow()
    try:
        delta = now - dt
    except TypeError:
        return None
    secs = int(delta.total_seconds())
    if secs < 0:
        return None
    if secs < 60:
        return "à l'instant"
    if secs < 3600:
        m = secs // 60
        return f"il y a {m} min"
    if secs < 86400:
        h = secs // 3600
        return f"il y a {h} h"
    d = secs // 86400
    if d == 1:
        return "depuis hier"
    return f"il y a {d} j"


def build_pending_action_items(db: Session) -> dict[str, Any]:
    """Actionable pending rows for the dashboard (omit zero-count categories)."""
    items: list[dict[str, Any]] = []

    # --- Demandes d'accès publiques ---
    from app.models import AccessRequest

    access_rows = (
        db.query(AccessRequest)
        .filter(AccessRequest.status == "pending")
        .order_by(AccessRequest.created_at.desc())
        .limit(200)
        .all()
    )
    if access_rows:
        n = len(access_rows)
        latest = access_rows[0]
        who = latest.username or latest.email or "—"
        rel = _fmt_relative(latest.created_at)
        summary = f"{n} {_plural(n, 'demande')} d'accès"
        if rel:
            summary = f"{summary} ({rel})"
        items.append(
            {
                "key": "access_requests",
                "label": "Demandes d'accès",
                "summary": summary,
                "detail": f"Dernière : {who}",
                "count": n,
                "href": "/admin/access-requests?status=pending",
                "severity": "info",
            }
        )

    # --- Nouveaux users SSO ---
    user_rows = (
        db.query(PendingUser)
        .filter(PendingUser.status == "pending")
        .order_by(PendingUser.last_seen_at.desc())
        .limit(200)
        .all()
    )
    if user_rows:
        n = len(user_rows)
        latest = user_rows[0]
        who = latest.user_email or "—"
        rel = _fmt_relative(latest.last_seen_at)
        if n == 1:
            summary = "1 nouvel utilisateur"
        else:
            summary = f"{n} nouveaux utilisateurs"
        if rel:
            summary = f"{summary} ({rel})"
        items.append(
            {
                "key": "pending_users",
                "label": "Nouveaux utilisateurs",
                "summary": summary,
                "detail": f"Dernier : {who}",
                "count": n,
                "href": "/admin/pending-users?status=pending",
                "severity": "info",
            }
        )

    # --- Domaines / Hosts inconnus ---
    host_rows = [
        r
        for r in (
            db.query(PendingHost)
            .filter(PendingHost.status == "pending")
            .order_by(PendingHost.last_seen_at.desc())
            .limit(200)
            .all()
        )
        if not is_infra_discovery_probe(r.hostname)
    ]
    if host_rows:
        n = len(host_rows)
        latest = host_rows[0]
        sample = latest.hostname or "—"
        if latest.last_uri:
            sample = f"{latest.hostname}{latest.last_uri}"
        rel = _fmt_relative(latest.last_seen_at)
        summary = f"{n} {_plural(n, 'domaine')} en attente"
        if rel:
            summary = f"{summary} ({rel})"
        items.append(
            {
                "key": "pending_hosts",
                "label": "Domaines",
                "summary": summary,
                "detail": f"Dernier vu : {sample}",
                "count": n,
                "href": "/admin/pending-hosts?status=pending",
                "severity": "warn",
            }
        )

    # --- Appareils ActiveSync (téléphones, tablettes, …) ---
    device_rows = (
        db.query(ActiveSyncDevice)
        .filter(ActiveSyncDevice.status == "pending")
        .order_by(ActiveSyncDevice.last_seen_at.desc())
        .limit(200)
        .all()
    )
    if device_rows:
        n = len(device_rows)
        latest = device_rows[0]
        who = latest.user_key or "—"
        rel = _fmt_relative(latest.last_seen_at)
        if n == 1:
            summary = "1 appareil en attente"
        else:
            summary = f"{n} appareils en attente"
        if rel:
            summary = f"{summary} ({rel})"
        items.append(
            {
                "key": "pending_devices",
                "label": "Appareils",
                "summary": summary,
                "detail": f"Dernier : {who}",
                "count": n,
                "href": "/admin/pending-devices?status=pending",
                "severity": "info",
            }
        )

    # --- Comptes bastion bloqués (Keycloak / provisioning) ---
    account_rows = (
        db.query(BastionAccount)
        .filter(BastionAccount.status.in_(("pending", "partial_failure")))
        .order_by(BastionAccount.updated_at.desc())
        .limit(200)
        .all()
    )
    if account_rows:
        n = len(account_rows)
        latest = account_rows[0]
        pending_kc = sum(1 for a in account_rows if a.status == "pending")
        failed = n - pending_kc
        bits: list[str] = []
        if pending_kc:
            bits.append(
                f"{pending_kc} {_plural(pending_kc, 'sans Keycloak')}"
            )
        if failed:
            bits.append(
                f"{failed} {_plural(failed, 'échec', 'échecs')} provisioning"
            )
        summary = f"{n} {_plural(n, 'compte')} bastion à traiter"
        detail = " · ".join(bits) if bits else (latest.username or "—")
        if latest.username and bits:
            detail = f"{detail} — ex. {latest.username}"
        items.append(
            {
                "key": "bastion_accounts",
                "label": "Comptes / sync",
                "summary": summary,
                "detail": detail,
                "count": n,
                "href": "/admin/rbac/users",
                "severity": "warn",
            }
        )

    total = sum(int(i["count"]) for i in items)
    return {"total": total, "entries": items}
