"""Shared pending-queue counters for sidebar, dashboard, and notifications.

Single source of truth for "éléments en attente" — no duplicated counting logic.
Only surfaces categories backed by real DB rows (never invents zero placeholders).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.bastion.pending_host_service import is_infra_discovery_probe
from app.i18n.catalog import t
from app.i18n.resolve import DEFAULT_LOCALE
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


def _fmt_relative(dt, locale: str | None = None) -> str | None:
    loc = locale or DEFAULT_LOCALE
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
        return t("à l'instant", loc)
    if secs < 3600:
        m = secs // 60
        return t("il y a {m} min", loc, m=m)
    if secs < 86400:
        h = secs // 3600
        return t("il y a {h} h", loc, h=h)
    d = secs // 86400
    if d == 1:
        return t("depuis hier", loc)
    return t("il y a {d} j", loc, d=d)


def _with_relative(summary: str, rel: str | None) -> str:
    return f"{summary} ({rel})" if rel else summary


def _pending_item(
    *,
    key: str,
    label: str,
    summary: str,
    detail: str,
    count: int,
    href: str,
    severity: str,
) -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "summary": summary,
        "detail": detail,
        "count": count,
        "href": href,
        "severity": severity,
    }


def _append_access_requests(db: Session, items: list[dict[str, Any]], loc: str) -> None:
    from app.models import AccessRequest

    rows = (
        db.query(AccessRequest)
        .filter(AccessRequest.status == "pending")
        .order_by(AccessRequest.created_at.desc())
        .limit(200)
        .all()
    )
    if not rows:
        return
    n = len(rows)
    latest = rows[0]
    who = latest.username or latest.email or "—"
    summary = (
        t("{n} demande d'accès", loc, n=n)
        if n == 1
        else t("{n} demandes d'accès", loc, n=n)
    )
    items.append(
        _pending_item(
            key="access_requests",
            label=t("Demandes d'accès", loc),
            summary=_with_relative(summary, _fmt_relative(latest.created_at, loc)),
            detail=t("Dernière : {who}", loc, who=who),
            count=n,
            href="/admin/access-requests?status=pending",
            severity="info",
        )
    )


def _append_pending_users(db: Session, items: list[dict[str, Any]], loc: str) -> None:
    rows = (
        db.query(PendingUser)
        .filter(PendingUser.status == "pending")
        .order_by(PendingUser.last_seen_at.desc())
        .limit(200)
        .all()
    )
    if not rows:
        return
    n = len(rows)
    latest = rows[0]
    summary = (
        t("1 nouvel utilisateur", loc)
        if n == 1
        else t("{n} nouveaux utilisateurs", loc, n=n)
    )
    items.append(
        _pending_item(
            key="pending_users",
            label=t("Nouveaux utilisateurs", loc),
            summary=_with_relative(summary, _fmt_relative(latest.last_seen_at, loc)),
            detail=t("Dernier : {who}", loc, who=latest.user_email or "—"),
            count=n,
            href="/admin/pending-users?status=pending",
            severity="info",
        )
    )


def _append_pending_hosts(db: Session, items: list[dict[str, Any]], loc: str) -> None:
    rows = [
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
    if not rows:
        return
    n = len(rows)
    latest = rows[0]
    sample = latest.hostname or "—"
    if latest.last_uri:
        sample = f"{latest.hostname}{latest.last_uri}"
    summary = (
        t("{n} domaine en attente", loc, n=n)
        if n == 1
        else t("{n} domaines en attente", loc, n=n)
    )
    items.append(
        _pending_item(
            key="pending_hosts",
            label=t("Domaines", loc),
            summary=_with_relative(summary, _fmt_relative(latest.last_seen_at, loc)),
            detail=t("Dernier vu : {sample}", loc, sample=sample),
            count=n,
            href="/admin/pending-hosts?status=pending",
            severity="warn",
        )
    )


def _append_pending_devices(db: Session, items: list[dict[str, Any]], loc: str) -> None:
    rows = (
        db.query(ActiveSyncDevice)
        .filter(ActiveSyncDevice.status == "pending")
        .order_by(ActiveSyncDevice.last_seen_at.desc())
        .limit(200)
        .all()
    )
    if not rows:
        return
    n = len(rows)
    latest = rows[0]
    summary = (
        t("1 appareil en attente", loc)
        if n == 1
        else t("{n} appareils en attente", loc, n=n)
    )
    items.append(
        _pending_item(
            key="pending_devices",
            label=t("Appareils", loc),
            summary=_with_relative(summary, _fmt_relative(latest.last_seen_at, loc)),
            detail=t("Dernier : {who}", loc, who=latest.user_key or "—"),
            count=n,
            href="/admin/pending-devices?status=pending",
            severity="info",
        )
    )


def _append_bastion_accounts(db: Session, items: list[dict[str, Any]], loc: str) -> None:
    rows = (
        db.query(BastionAccount)
        .filter(BastionAccount.status.in_(("pending", "partial_failure")))
        .order_by(BastionAccount.updated_at.desc())
        .limit(200)
        .all()
    )
    if not rows:
        return
    n = len(rows)
    latest = rows[0]
    pending_kc = sum(1 for a in rows if a.status == "pending")
    failed = n - pending_kc
    bits: list[str] = []
    if pending_kc:
        bits.append(t("{n} sans Keycloak", loc, n=pending_kc))
    if failed:
        bits.append(
            t("{n} échec provisioning", loc, n=failed)
            if failed == 1
            else t("{n} échecs provisioning", loc, n=failed)
        )
    summary = (
        t("{n} compte bastion à traiter", loc, n=n)
        if n == 1
        else t("{n} comptes bastion à traiter", loc, n=n)
    )
    detail = " · ".join(bits) if bits else (latest.username or "—")
    if latest.username and bits:
        detail = t(
            "{detail} — ex. {username}",
            loc,
            detail=detail,
            username=latest.username,
        )
    items.append(
        _pending_item(
            key="bastion_accounts",
            label=t("Comptes / sync", loc),
            summary=summary,
            detail=detail,
            count=n,
            href="/admin/rbac/users",
            severity="warn",
        )
    )


def build_pending_action_items(
    db: Session,
    locale: str | None = None,
) -> dict[str, Any]:
    """Actionable pending rows for the dashboard (omit zero-count categories)."""
    loc = locale or DEFAULT_LOCALE
    items: list[dict[str, Any]] = []
    _append_access_requests(db, items, loc)
    _append_pending_users(db, items, loc)
    _append_pending_hosts(db, items, loc)
    _append_pending_devices(db, items, loc)
    _append_bastion_accounts(db, items, loc)
    total = sum(int(i["count"]) for i in items)
    return {"total": total, "entries": items}
