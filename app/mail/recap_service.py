"""Daily ops recap email — discovered domains, pending accounts, recent alerts.

Uses the global SMTP config on PortalSettings. Scheduled on the health-probe
leader; never raises out of the job wrapper.
"""

from __future__ import annotations

import html
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy.orm import Session

from app.audit import log_action
from app.bastion.pending_host_service import is_infra_discovery_probe
from app.mail.smtp_service import SmtpError, send_email, smtp_configured
from app.models import (
    AccessRequest,
    BastionAccount,
    PendingHost,
    PendingUser,
    PortalSettings,
    SecurityBan,
    utcnow,
)
from app.portal_settings_service import ensure_portal_settings
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

RECAP_TZ_NAME = "Europe/Paris"
LIST_CAP = 15
ALERT_CAP = 25
WINDOW_HOURS = 24

_MONTHS_FR = (
    "janvier",
    "février",
    "mars",
    "avril",
    "mai",
    "juin",
    "juillet",
    "août",
    "septembre",
    "octobre",
    "novembre",
    "décembre",
)


def recap_timezone() -> tzinfo:
    """Europe/Paris when tzdata is available, else UTC."""
    try:
        return ZoneInfo(RECAP_TZ_NAME)
    except ZoneInfoNotFoundError:
        return UTC


def recap_window_start(*, now: datetime | None = None) -> datetime:
    stamp = now or utcnow()
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return stamp.astimezone(UTC) - timedelta(hours=WINDOW_HOURS)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _in_window(dt: datetime | None, since: datetime) -> bool:
    aware = _as_utc(dt)
    since_utc = _as_utc(since)
    if aware is None or since_utc is None:
        return False
    return aware >= since_utc


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _fmt_dt(dt: datetime | None) -> str:
    aware = _as_utc(dt)
    if aware is None:
        return "—"
    return aware.strftime("%Y-%m-%d %H:%M UTC")


def _fmt_date_fr(dt: datetime) -> str:
    local = dt.astimezone(recap_timezone()) if dt.tzinfo else dt
    return f"{local.day} {_MONTHS_FR[local.month - 1]} {local.year}"


def _admin_base(settings: Settings) -> str:
    domain = (settings.portal_domain or "").strip()
    if not domain:
        return ""
    if domain.startswith(("http://", "https://")):
        return domain.rstrip("/")
    return f"https://{domain}"


def recap_recipient(row: PortalSettings) -> str | None:
    dedicated = (getattr(row, "daily_recap_email", None) or "").strip()
    if dedicated and "@" in dedicated:
        return dedicated
    fallback = (row.smtp_from_email or "").strip()
    if fallback and "@" in fallback:
        return fallback
    return None


def recap_hour(row: PortalSettings) -> int:
    try:
        hour = int(getattr(row, "daily_recap_hour", None) or 7)
    except (TypeError, ValueError):
        hour = 7
    return max(0, min(23, hour))


@dataclass
class RecapLine:
    title: str
    detail: str = ""
    href: str = ""


@dataclass
class DailyRecap:
    since: datetime
    until: datetime
    portal_url: str
    new_hosts: list[RecapLine] = field(default_factory=list)
    new_hosts_count: int = 0
    pending_hosts_total: int = 0
    new_users: list[RecapLine] = field(default_factory=list)
    pending_users_total: int = 0
    new_access_requests: list[RecapLine] = field(default_factory=list)
    pending_access_total: int = 0
    pending_accounts: list[RecapLine] = field(default_factory=list)
    pending_accounts_count: int = 0
    alerts: list[RecapLine] = field(default_factory=list)
    alerts_total: int = 0
    bans: list[RecapLine] = field(default_factory=list)

    @property
    def pending_accounts_total(self) -> int:
        return (
            self.pending_users_total
            + self.pending_access_total
            + self.pending_accounts_count
        )

    @property
    def noteworthy(self) -> bool:
        return bool(
            self.new_hosts
            or self.pending_hosts_total
            or self.pending_accounts_total
            or self.alerts_total
            or self.bans
        )


@dataclass(frozen=True)
class RecapSendResult:
    status: str
    message: str


def build_daily_recap(
    db: Session,
    settings: Settings,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
) -> DailyRecap:
    until_dt = until or utcnow()
    if until_dt.tzinfo is None:
        until_dt = until_dt.replace(tzinfo=UTC)
    since_dt = since or recap_window_start(now=until_dt)
    base = _admin_base(settings)
    recap = DailyRecap(since=since_dt, until=until_dt, portal_url=base)

    host_href = f"{base}/admin/pending-hosts?status=pending" if base else "/admin/pending-hosts?status=pending"
    user_href = f"{base}/admin/pending-users?status=pending" if base else "/admin/pending-users?status=pending"
    access_href = f"{base}/admin/access-requests?status=pending" if base else "/admin/access-requests?status=pending"
    accounts_href = f"{base}/admin/rbac/users" if base else "/admin/rbac/users"
    logs_href = f"{base}/admin/logs" if base else "/admin/logs"

    host_rows = [
        row
        for row in (
            db.query(PendingHost)
            .filter(PendingHost.status == "pending")
            .order_by(PendingHost.last_seen_at.desc())
            .all()
        )
        if not is_infra_discovery_probe(row.hostname)
    ]
    recap.pending_hosts_total = len(host_rows)
    new_hosts = [row for row in host_rows if _in_window(row.first_seen_at, since_dt)]
    recap.new_hosts_count = len(new_hosts)
    recap.new_hosts = [
        RecapLine(
            title=row.hostname,
            detail=(
                f"vu {_fmt_dt(row.last_seen_at)}"
                + (f" · {row.hit_count} hits" if row.hit_count else "")
                + (f" · {row.last_client_ip}" if row.last_client_ip else "")
            ),
            href=host_href,
        )
        for row in new_hosts[:LIST_CAP]
    ]

    user_rows = (
        db.query(PendingUser)
        .filter(PendingUser.status == "pending")
        .order_by(PendingUser.last_seen_at.desc())
        .all()
    )
    recap.pending_users_total = len(user_rows)
    recap.new_users = [
        RecapLine(
            title=row.user_email or row.username or "—",
            detail=(
                f"{row.realm_slug} · vu {_fmt_dt(row.last_seen_at)}"
                + (" · nouveau 24h" if _in_window(row.first_seen_at, since_dt) else "")
            ),
            href=user_href,
        )
        for row in user_rows[:LIST_CAP]
    ]

    access_rows = (
        db.query(AccessRequest)
        .filter(AccessRequest.status == "pending")
        .order_by(AccessRequest.created_at.desc())
        .all()
    )
    recap.pending_access_total = len(access_rows)
    recap.new_access_requests = [
        RecapLine(
            title=row.username or row.email or "—",
            detail=(
                f"{row.email}"
                + (f" · {row.organization}" if row.organization else "")
                + f" · {_fmt_dt(row.created_at)}"
                + (" · nouveau 24h" if _in_window(row.created_at, since_dt) else "")
            ),
            href=access_href,
        )
        for row in access_rows[:LIST_CAP]
    ]

    account_q = db.query(BastionAccount).filter(
        BastionAccount.status.in_(("pending", "partial_failure"))
    )
    recap.pending_accounts_count = account_q.count()
    account_rows = account_q.order_by(BastionAccount.updated_at.desc()).limit(LIST_CAP).all()
    recap.pending_accounts = [
        RecapLine(
            title=row.username or row.email or "—",
            detail=(
                f"{row.status}"
                + (f" · {row.last_error}" if row.last_error else "")
            ),
            href=accounts_href,
        )
        for row in account_rows
    ]

    from app.web.admin_logs_query import list_admin_log_entries

    entries, alerts_total, _ = list_admin_log_entries(
        db,
        date_from=since_dt,
        date_to=until_dt,
        severity_min="WARNING",
        limit=ALERT_CAP,
    )
    recap.alerts_total = alerts_total
    recap.alerts = [
        RecapLine(
            title=(
                f"{e.get('event_code') or ''} "
                f"{e.get('event_title_fr') or e.get('action') or ''}"
            ).strip(),
            detail=(
                f"{e.get('catalog_severity') or e.get('severity') or ''} · "
                f"{e.get('actor') or '—'} · {e.get('timestamp') or ''}"
                + (f" · {e.get('detail_short')}" if e.get("detail_short") else "")
            ).strip(" ·"),
            href=logs_href,
        )
        for e in entries
    ]

    ban_rows = (
        db.query(SecurityBan)
        .filter(SecurityBan.banned_at >= since_dt)
        .order_by(SecurityBan.banned_at.desc())
        .limit(LIST_CAP)
        .all()
    )
    recap.bans = [
        RecapLine(
            title=f"{row.target_type}:{row.target}",
            detail=(
                f"{row.reason or row.rule_type or 'ban'} · {_fmt_dt(row.banned_at)}"
                + (" · permanent" if row.permanent else "")
            ),
            href=logs_href,
        )
        for row in ban_rows
    ]
    return recap


def format_recap_email(recap: DailyRecap) -> tuple[str, str, str]:
    date_label = _fmt_date_fr(recap.until)
    n_hosts = recap.new_hosts_count
    n_pending = recap.pending_accounts_total
    n_alerts = recap.alerts_total + len(recap.bans)
    if recap.noteworthy:
        bits = []
        if n_hosts or recap.pending_hosts_total:
            bits.append(
                f"{n_hosts} domaine{'s' if n_hosts != 1 else ''} découvert"
                f"{'s' if n_hosts != 1 else ''}"
            )
        if n_pending:
            bits.append(f"{n_pending} compte{'s' if n_pending != 1 else ''} en attente")
        if n_alerts:
            bits.append(f"{n_alerts} alerte{'s' if n_alerts != 1 else ''}")
        subject = f"[Portail] Récap 24h — {', '.join(bits)} ({date_label})"
    else:
        subject = f"[Portail] Récap 24h — rien à signaler ({date_label})"

    text = _recap_text(recap, date_label)
    html_body = _recap_html(recap, date_label)
    return subject, text, html_body


def _section_text(
    title: str,
    lines: list[RecapLine],
    *,
    empty: str,
    extra: str = "",
    omitted: int = 0,
) -> str:
    parts = [title]
    if extra:
        parts.append(extra)
    if not lines:
        parts.append(empty)
    else:
        for line in lines:
            parts.append(f"- {line.title}" + (f" — {line.detail}" if line.detail else ""))
        if omitted:
            parts.append(f"- … et {omitted} de plus")
    parts.append("")
    return "\n".join(parts)


def _recap_text(recap: DailyRecap, date_label: str) -> str:
    window = f"Fenêtre : {_fmt_dt(recap.since)} → {_fmt_dt(recap.until)}"
    parts = [
        f"Récapitulatif quotidien du portail — {date_label}",
        window,
        "",
        _section_text(
            "Domaines découverts (24h)",
            recap.new_hosts,
            empty="Aucun nouveau domaine en attente sur 24h.",
            extra=(
                f"Toujours en file : {recap.pending_hosts_total}."
                if recap.pending_hosts_total
                else ""
            ),
            omitted=max(0, recap.new_hosts_count - len(recap.new_hosts)),
        ),
        _section_text(
            "Comptes en attente",
            recap.new_users + recap.new_access_requests + recap.pending_accounts,
            empty="Aucun compte en attente.",
            extra=(
                f"Utilisateurs SSO : {recap.pending_users_total} · "
                f"Demandes d'accès : {recap.pending_access_total} · "
                f"Comptes bastion : {recap.pending_accounts_count}."
            ),
        ),
        _section_text(
            "Alertes (WARNING et plus)",
            recap.alerts,
            empty="Aucune alerte sur 24h.",
            extra=f"Total : {recap.alerts_total}." if recap.alerts_total else "",
            omitted=max(0, recap.alerts_total - len(recap.alerts)),
        ),
        _section_text(
            "Bannissements (24h)",
            recap.bans,
            empty="Aucun nouveau bannissement.",
        ),
    ]
    if recap.portal_url:
        parts.append(f"Admin : {recap.portal_url}/admin")
        parts.append(f"Domaines : {recap.portal_url}/admin/pending-hosts")
        parts.append(f"Utilisateurs : {recap.portal_url}/admin/pending-users")
        parts.append(f"Logs : {recap.portal_url}/admin/logs")
    return "\n".join(parts).rstrip() + "\n"


def _html_list(lines: list[RecapLine], *, omitted: int = 0) -> str:
    if not lines:
        return ""
    items = []
    for line in lines:
        title = _esc(line.title)
        if line.href:
            title = f'<a href="{_esc(line.href)}">{title}</a>'
        detail = f"<br><small>{_esc(line.detail)}</small>" if line.detail else ""
        items.append(f"<li>{title}{detail}</li>")
    if omitted:
        items.append(f"<li>… et {_esc(omitted)} de plus</li>")
    return "<ul>" + "".join(items) + "</ul>"


def _recap_html(recap: DailyRecap, date_label: str) -> str:
    empty_hosts = "<p>Aucun nouveau domaine en attente sur 24h.</p>"
    empty_accounts = "<p>Aucun compte en attente.</p>"
    empty_alerts = "<p>Aucune alerte sur 24h.</p>"
    empty_bans = "<p>Aucun nouveau bannissement.</p>"
    hosts_html = _html_list(
        recap.new_hosts,
        omitted=max(0, recap.new_hosts_count - len(recap.new_hosts)),
    ) or empty_hosts
    accounts_lines = recap.new_users + recap.new_access_requests + recap.pending_accounts
    accounts_html = _html_list(accounts_lines) or empty_accounts
    alerts_html = (
        _html_list(
            recap.alerts,
            omitted=max(0, recap.alerts_total - len(recap.alerts)),
        )
        or empty_alerts
    )
    bans_html = _html_list(recap.bans) or empty_bans
    links = ""
    if recap.portal_url:
        links = (
            "<p>"
            f'<a href="{_esc(recap.portal_url)}/admin/pending-hosts">Domaines</a> · '
            f'<a href="{_esc(recap.portal_url)}/admin/pending-users">Utilisateurs</a> · '
            f'<a href="{_esc(recap.portal_url)}/admin/access-requests">Demandes d\'accès</a> · '
            f'<a href="{_esc(recap.portal_url)}/admin/logs">Logs</a>'
            "</p>"
        )
    return (
        f"<p>Récapitulatif quotidien du portail — {_esc(date_label)}</p>"
        f"<p>Fenêtre : {_esc(_fmt_dt(recap.since))} → {_esc(_fmt_dt(recap.until))}</p>"
        "<h2>Domaines découverts (24h)</h2>"
        f"<p>Toujours en file : {recap.pending_hosts_total}.</p>"
        f"{hosts_html}"
        "<h2>Comptes en attente</h2>"
        "<p>"
        f"Utilisateurs SSO : {recap.pending_users_total} · "
        f"Demandes d'accès : {recap.pending_access_total} · "
        f"Comptes bastion : {recap.pending_accounts_count}."
        "</p>"
        f"{accounts_html}"
        "<h2>Alertes (WARNING et plus)</h2>"
        f"<p>Total : {recap.alerts_total}.</p>"
        f"{alerts_html}"
        "<h2>Bannissements (24h)</h2>"
        f"{bans_html}"
        f"{links}"
    )


def _already_sent_today(row: PortalSettings, now_local: datetime) -> bool:
    last = _as_utc(getattr(row, "daily_recap_last_sent_at", None))
    if last is None:
        return False
    last_local = last.astimezone(now_local.tzinfo)
    return last_local.date() == now_local.date()


def send_daily_recap(
    db: Session,
    settings: Settings,
    *,
    force: bool = False,
    actor: str = "scheduler",
    now: datetime | None = None,
) -> RecapSendResult:
    """Send the 24h recap when enabled (or force=True from the admin UI)."""
    row = ensure_portal_settings(db, settings)
    enabled = bool(getattr(row, "daily_recap_enabled", False))
    if not force and not enabled:
        return RecapSendResult("skipped_disabled", "Récap quotidien désactivé")
    if not smtp_configured(row):
        return RecapSendResult(
            "skipped_smtp",
            "SMTP non configuré — activez-le dans Configuration",
        )
    to_email = recap_recipient(row)
    if not to_email:
        return RecapSendResult(
            "skipped_no_recipient",
            "Aucun destinataire (email récap ou expéditeur SMTP)",
        )

    tz = recap_timezone()
    stamp = now or datetime.now(tz)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=tz)
    now_local = stamp.astimezone(tz)

    if not force:
        hour = recap_hour(row)
        if now_local.hour < hour:
            return RecapSendResult(
                "skipped_hour",
                f"Heure d'envoi non atteinte ({hour:02d}h {RECAP_TZ_NAME})",
            )
        if _already_sent_today(row, now_local):
            return RecapSendResult("skipped_already", "Récap déjà envoyé aujourd'hui")

    recap = build_daily_recap(db, settings, until=_as_utc(stamp))
    subject, body_text, body_html = format_recap_email(recap)
    try:
        send_email(
            row,
            settings,
            to_email=to_email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
        )
    except SmtpError as exc:
        log_action(
            db,
            actor=actor,
            action="portal_settings.daily_recap_failed",
            target="portal_settings",
            details={"ok": False, "error": str(exc), "to": to_email},
            forward_to_siem=True,
        )
        logger.warning("daily recap send failed: %s", exc)
        return RecapSendResult("error", str(exc))

    row.daily_recap_last_sent_at = utcnow()
    db.commit()
    log_action(
        db,
        actor=actor,
        action="portal_settings.daily_recap_sent",
        target="portal_settings",
        details={
            "ok": True,
            "to": to_email,
            "new_hosts": len(recap.new_hosts),
            "pending_hosts": recap.pending_hosts_total,
            "pending_accounts": recap.pending_accounts_total,
            "alerts": recap.alerts_total,
            "bans": len(recap.bans),
            "force": bool(force),
        },
        forward_to_siem=False,
    )
    return RecapSendResult("sent", f"Récap envoyé à {to_email}")


def daily_recap_job(settings: Settings) -> None:
    """Cron entrypoint — never raises."""
    from app.database import SessionLocal

    try:
        db = SessionLocal()
        try:
            result = send_daily_recap(db, settings)
            if result.status == "sent":
                logger.info("daily recap: %s", result.message)
            elif result.status == "error":
                logger.warning("daily recap: %s", result.message)
            else:
                logger.debug("daily recap skipped: %s", result.status)
        finally:
            db.close()
    except Exception:
        logger.exception("daily recap job failed")


__all__ = [
    "DailyRecap",
    "RecapLine",
    "RecapSendResult",
    "build_daily_recap",
    "daily_recap_job",
    "format_recap_email",
    "recap_hour",
    "recap_recipient",
    "recap_timezone",
    "recap_window_start",
    "send_daily_recap",
]
