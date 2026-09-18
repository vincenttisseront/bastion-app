"""Daily ops recap email — discovered domains, pending accounts, devices, recent alerts.

Uses the global SMTP config on PortalSettings. Scheduled on the health-probe
leader; never raises out of the job wrapper.
"""

from __future__ import annotations

import html
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any
from urllib.parse import urlencode
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy.orm import Session

from app.audit import log_action
from app.bastion.pending_host_service import is_infra_discovery_probe
from app.i18n.catalog import t
from app.i18n.resolve import DEFAULT_LOCALE, normalize_locale
from app.mail.smtp_service import SmtpError, send_email, smtp_configured
from app.models import (
    AccessRequest,
    ActiveSyncDevice,
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


def _fmt_date_fr(dt: datetime, locale: str | None = None) -> str:
    loc = normalize_locale(locale) or DEFAULT_LOCALE
    local = dt.astimezone(recap_timezone()) if dt.tzinfo else dt
    month = t(_MONTHS_FR[local.month - 1], loc)
    return f"{local.day} {month} {local.year}"


def _loc(locale: str | None) -> str:
    return normalize_locale(locale) or DEFAULT_LOCALE


def _admin_base(settings: Settings) -> str:
    domain = (settings.portal_domain or "").strip()
    if not domain:
        return ""
    if domain.startswith(("http://", "https://")):
        return domain.rstrip("/")
    return f"https://{domain}"


def _admin_path(portal_base: str, path: str, *, query: dict[str, Any] | None = None, fragment: str = "") -> str:
    base = (portal_base or "").rstrip("/")
    path = path if path.startswith("/") else f"/{path}"
    url = f"{base}{path}" if base else path
    if query:
        cleaned = {k: v for k, v in query.items() if v is not None and str(v).strip() != ""}
        if cleaned:
            url = f"{url}?{urlencode(cleaned)}"
    if fragment:
        url = f"{url}#{fragment.lstrip('#')}"
    return url


def _audit_entry_href(portal_base: str, entry: dict[str, Any]) -> str:
    """Deep-link that focuses a single audit row (`?id=` opens the drawer)."""
    query: dict[str, Any] = {}
    aid = entry.get("id")
    if aid is not None:
        query["id"] = int(aid)
    code = (entry.get("event_code") or "").strip()
    if code:
        query["event_code"] = code
    return _admin_path(portal_base, "/admin/logs", query=query, fragment="audit")


def _logs_severity_href(portal_base: str, *, since: datetime, severity_min: str = "WARNING") -> str:
    return _admin_path(
        portal_base,
        "/admin/logs",
        query={
            "severity_min": severity_min,
            "date_from": since.date().isoformat(),
        },
        fragment="audit",
    )


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
    severity: str = ""
    meta: str = ""
    code: str = ""


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
    pending_devices: list[RecapLine] = field(default_factory=list)
    pending_devices_total: int = 0
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
            or self.pending_devices_total
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

    host_href = _admin_path(base, "/admin/pending-hosts", query={"status": "pending"})
    user_href = _admin_path(base, "/admin/pending-users", query={"status": "pending"})
    device_href = _admin_path(base, "/admin/pending-devices", query={"status": "pending"})
    access_href = _admin_path(base, "/admin/access-requests", query={"status": "pending"})
    accounts_href = _admin_path(base, "/admin/rbac/users")

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

    device_rows = (
        db.query(ActiveSyncDevice)
        .filter(ActiveSyncDevice.status == "pending")
        .order_by(ActiveSyncDevice.last_seen_at.desc())
        .all()
    )
    recap.pending_devices_total = len(device_rows)
    recap.pending_devices = [
        RecapLine(
            title=row.user_key or "—",
            detail=(
                f"{(row.device_type or row.device_id or 'appareil')[:40]}"
                + f" · vu {_fmt_dt(row.last_seen_at)}"
                + (f" · {row.request_count} hits" if row.request_count else "")
                + (" · nouveau 24h" if _in_window(row.first_seen_at, since_dt) else "")
            ),
            href=device_href,
        )
        for row in device_rows[:LIST_CAP]
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
    recap.alerts = []
    for e in entries:
        code = (e.get("event_code") or "").strip()
        title_fr = (e.get("event_title_fr") or e.get("action") or "").strip()
        sev = (e.get("catalog_severity") or e.get("severity") or "").strip().upper()
        actor = (e.get("actor") or "—").strip()
        ts = (e.get("timestamp") or "").strip()
        target = (e.get("target") or "").strip()
        detail_bits = [p for p in (sev, actor, ts, target, e.get("detail_short") or "") if p]
        recap.alerts.append(
            RecapLine(
                title=f"{code} {title_fr}".strip() if code else title_fr,
                detail=" · ".join(str(p) for p in detail_bits),
                href=_audit_entry_href(base, e),
                severity=sev,
                meta=f"{actor} · {ts}" if ts else actor,
                code=code,
            )
        )

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
            href=_admin_path(
                base,
                "/admin/logs",
                query={"q": row.target, "date_from": since_dt.date().isoformat()},
                fragment="audit",
            ),
            severity="WARNING",
        )
        for row in ban_rows
    ]
    return recap


def format_recap_email(
    recap: DailyRecap,
    *,
    locale: str | None = None,
) -> tuple[str, str, str]:
    loc = _loc(locale)
    date_label = _fmt_date_fr(recap.until, loc)
    n_hosts = recap.new_hosts_count
    n_pending = recap.pending_accounts_total
    n_alerts = recap.alerts_total + len(recap.bans)
    if recap.noteworthy:
        bits = []
        if n_hosts or recap.pending_hosts_total:
            bits.append(
                t(
                    "{n} domaine découvert",
                    loc,
                    n=n_hosts,
                )
                if n_hosts == 1
                else t("{n} domaines découverts", loc, n=n_hosts)
            )
        if n_pending:
            bits.append(
                t("{n} compte en attente", loc, n=n_pending)
                if n_pending == 1
                else t("{n} comptes en attente", loc, n=n_pending)
            )
        if recap.pending_devices_total:
            n_dev = recap.pending_devices_total
            bits.append(
                t("{n} appareil en attente", loc, n=n_dev)
                if n_dev == 1
                else t("{n} appareils en attente", loc, n=n_dev)
            )
        if n_alerts:
            bits.append(
                t("{n} alerte", loc, n=n_alerts)
                if n_alerts == 1
                else t("{n} alertes", loc, n=n_alerts)
            )
        subject = t(
            "[Portail] Récap 24h — {bits} ({date_label})",
            loc,
            bits=", ".join(bits),
            date_label=date_label,
        )
    else:
        subject = t(
            "[Portail] Récap 24h — rien à signaler ({date_label})",
            loc,
            date_label=date_label,
        )

    text = _recap_text(recap, date_label, locale=loc)
    html_body = _recap_html(recap, date_label, locale=loc)
    return subject, text, html_body


def _section_text(
    title: str,
    lines: list[RecapLine],
    *,
    empty: str,
    extra: str = "",
    omitted: int = 0,
    locale: str | None = None,
) -> str:
    loc = _loc(locale)
    parts = [title]
    if extra:
        parts.append(extra)
    if not lines:
        parts.append(empty)
    else:
        for line in lines:
            item = f"- {line.title}" + (f" — {line.detail}" if line.detail else "")
            if line.href:
                item = f"{item}\n  {line.href}"
            parts.append(item)
        if omitted:
            parts.append(t("- … et {omitted} de plus", loc, omitted=omitted))
    parts.append("")
    return "\n".join(parts)


def _recap_text(
    recap: DailyRecap,
    date_label: str,
    *,
    locale: str | None = None,
) -> str:
    loc = _loc(locale)
    window = t(
        "Fenêtre : {since} → {until}",
        loc,
        since=_fmt_dt(recap.since),
        until=_fmt_dt(recap.until),
    )
    parts = [
        t(
            "Récapitulatif quotidien du portail — {date_label}",
            loc,
            date_label=date_label,
        ),
        window,
        "",
        _section_text(
            t("Domaines découverts (24h)", loc),
            recap.new_hosts,
            empty=t("Aucun nouveau domaine en attente sur 24h.", loc),
            extra=(
                t("Toujours en file : {n}.", loc, n=recap.pending_hosts_total)
                if recap.pending_hosts_total
                else ""
            ),
            omitted=max(0, recap.new_hosts_count - len(recap.new_hosts)),
            locale=loc,
        ),
        _section_text(
            t("Comptes en attente", loc),
            recap.new_users + recap.new_access_requests + recap.pending_accounts,
            empty=t("Aucun compte en attente.", loc),
            extra=t(
                "Utilisateurs SSO : {users} · Demandes d'accès : {access} · "
                "Comptes bastion : {accounts}.",
                loc,
                users=recap.pending_users_total,
                access=recap.pending_access_total,
                accounts=recap.pending_accounts_count,
            ),
            locale=loc,
        ),
        _section_text(
            t("Appareils ActiveSync en attente", loc),
            recap.pending_devices,
            empty=t("Aucun appareil en attente.", loc),
            extra=(
                t("Toujours en file : {n}.", loc, n=recap.pending_devices_total)
                if recap.pending_devices_total
                else ""
            ),
            omitted=max(0, recap.pending_devices_total - len(recap.pending_devices)),
            locale=loc,
        ),
        _section_text(
            t("Alertes (WARNING et plus)", loc),
            recap.alerts,
            empty=t("Aucune alerte sur 24h.", loc),
            extra=(
                t("Total : {n}.", loc, n=recap.alerts_total)
                if recap.alerts_total
                else ""
            ),
            omitted=max(0, recap.alerts_total - len(recap.alerts)),
            locale=loc,
        ),
        _section_text(
            t("Bannissements (24h)", loc),
            recap.bans,
            empty=t("Aucun nouveau bannissement.", loc),
            locale=loc,
        ),
    ]
    if recap.portal_url:
        parts.append(
            f"{t('Admin', loc)} : {_admin_path(recap.portal_url, '/admin/configuration')}\n"
            f"{t('Domaines', loc)} : {_admin_path(recap.portal_url, '/admin/pending-hosts', query={'status': 'pending'})}\n"
            f"{t('Utilisateurs', loc)} : {_admin_path(recap.portal_url, '/admin/pending-users', query={'status': 'pending'})}\n"
            f"{t('Appareils', loc)} : {_admin_path(recap.portal_url, '/admin/pending-devices', query={'status': 'pending'})}\n"
            f"{t('Logs', loc)} : {_logs_severity_href(recap.portal_url, since=recap.since)}"
        )
    return "\n".join(parts).rstrip() + "\n"


def _severity_color(severity: str) -> str:
    sev = (severity or "").upper()
    if sev == "CRITICAL":
        return "#b91c1c"
    if sev == "ERROR":
        return "#dc2626"
    if sev == "WARNING":
        return "#d97706"
    if sev == "NOTICE":
        return "#2563eb"
    return "#64748b"


def _html_list(
    lines: list[RecapLine],
    *,
    omitted: int = 0,
    locale: str | None = None,
) -> str:
    loc = _loc(locale)
    if not lines:
        return ""
    rows: list[str] = []
    for line in lines:
        title = _esc(line.title)
        if line.href:
            title = (
                f'<a href="{_esc(line.href)}" style="color:#0f766e;text-decoration:none;font-weight:600;">'
                f"{title}</a>"
            )
        detail = (
            f'<div style="margin-top:4px;color:#64748b;font-size:12px;line-height:1.4;">'
            f"{_esc(line.detail)}</div>"
            if line.detail
            else ""
        )
        badge = ""
        if line.severity:
            color = _severity_color(line.severity)
            badge = (
                f'<span style="display:inline-block;margin-right:8px;padding:2px 8px;'
                f"border-radius:999px;background:{color};color:#fff;font-size:11px;"
                f'font-weight:700;letter-spacing:.02em;">{_esc(line.severity)}</span>'
            )
        rows.append(
            '<tr>'
            f'<td style="padding:12px 0;border-bottom:1px solid #e2e8f0;vertical-align:top;">'
            f"{badge}{title}{detail}"
            f"</td></tr>"
        )
    if omitted:
        rows.append(
            '<tr><td style="padding:10px 0;color:#64748b;font-size:12px;">'
            f"{_esc(t('… et {omitted} de plus', loc, omitted=omitted))}</td></tr>"
        )
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="border-collapse:collapse;">'
        + "".join(rows)
        + "</table>"
    )


def _html_section(title: str, body: str, *, subtitle: str = "", cta_href: str = "", cta_label: str = "") -> str:
    cta = ""
    if cta_href and cta_label:
        cta = (
            f'<a href="{_esc(cta_href)}" style="float:right;font-size:12px;color:#0f766e;'
            f'text-decoration:none;font-weight:600;">{_esc(cta_label)} →</a>'
        )
    sub = (
        f'<p style="margin:4px 0 12px;color:#64748b;font-size:13px;">{_esc(subtitle)}</p>'
        if subtitle
        else ""
    )
    return (
        f'<tr><td style="padding:20px 24px 8px;">'
        f'<h2 style="margin:0;font-size:16px;line-height:1.3;color:#0f172a;">'
        f"{cta}{_esc(title)}</h2>"
        f"{sub}"
        f"{body}"
        f"</td></tr>"
    )


def _recap_html(
    recap: DailyRecap,
    date_label: str,
    *,
    locale: str | None = None,
) -> str:
    loc = _loc(locale)
    empty_hosts = (
        f'<p style="margin:0;color:#64748b;font-size:13px;">'
        f'{_esc(t("Aucun nouveau domaine en attente sur 24h.", loc))}</p>'
    )
    empty_accounts = (
        f'<p style="margin:0;color:#64748b;font-size:13px;">'
        f'{_esc(t("Aucun compte en attente.", loc))}</p>'
    )
    empty_devices = (
        f'<p style="margin:0;color:#64748b;font-size:13px;">'
        f'{_esc(t("Aucun appareil en attente.", loc))}</p>'
    )
    empty_alerts = (
        f'<p style="margin:0;color:#64748b;font-size:13px;">'
        f'{_esc(t("Aucune alerte sur 24h.", loc))}</p>'
    )
    empty_bans = (
        f'<p style="margin:0;color:#64748b;font-size:13px;">'
        f'{_esc(t("Aucun nouveau bannissement.", loc))}</p>'
    )

    hosts_html = _html_list(
        recap.new_hosts,
        omitted=max(0, recap.new_hosts_count - len(recap.new_hosts)),
        locale=loc,
    ) or empty_hosts
    accounts_lines = recap.new_users + recap.new_access_requests + recap.pending_accounts
    accounts_html = _html_list(accounts_lines, locale=loc) or empty_accounts
    devices_html = (
        _html_list(
            recap.pending_devices,
            omitted=max(0, recap.pending_devices_total - len(recap.pending_devices)),
            locale=loc,
        )
        or empty_devices
    )
    alerts_html = (
        _html_list(
            recap.alerts,
            omitted=max(0, recap.alerts_total - len(recap.alerts)),
            locale=loc,
        )
        or empty_alerts
    )
    bans_html = _html_list(recap.bans, locale=loc) or empty_bans

    hosts_cta = _admin_path(recap.portal_url, "/admin/pending-hosts", query={"status": "pending"})
    users_cta = _admin_path(recap.portal_url, "/admin/pending-users", query={"status": "pending"})
    devices_cta = _admin_path(recap.portal_url, "/admin/pending-devices", query={"status": "pending"})
    access_cta = _admin_path(recap.portal_url, "/admin/access-requests", query={"status": "pending"})
    logs_cta = _logs_severity_href(recap.portal_url, since=recap.since)
    admin_cta = _admin_path(recap.portal_url, "/admin/configuration")

    footer_links = ""
    if recap.portal_url:
        # Label extracted: py311 forbids backslash / quote reuse inside f-string exprs.
        access_requests_label = t("Demandes d'accès", loc)
        footer_links = (
            '<p style="margin:0 0 8px;">'
            f'<a href="{_esc(hosts_cta)}" style="color:#0f766e;text-decoration:none;">{_esc(t("Domaines", loc))}</a>'
            " · "
            f'<a href="{_esc(users_cta)}" style="color:#0f766e;text-decoration:none;">{_esc(t("Utilisateurs", loc))}</a>'
            " · "
            f'<a href="{_esc(devices_cta)}" style="color:#0f766e;text-decoration:none;">{_esc(t("Appareils", loc))}</a>'
            " · "
            f'<a href="{_esc(access_cta)}" style="color:#0f766e;text-decoration:none;">{_esc(access_requests_label)}</a>'
            " · "
            f'<a href="{_esc(logs_cta)}" style="color:#0f766e;text-decoration:none;">{_esc(t("Logs sécurité", loc))}</a>'
            "</p>"
        )

    return f"""<!DOCTYPE html>
<html lang="{_esc(loc)}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(t("Récapitulatif quotidien", loc))}</title></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0f172a;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="max-width:640px;width:100%;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">
<tr><td style="padding:20px 24px;background:#0f766e;color:#ffffff;">
  <div style="font-size:12px;letter-spacing:.08em;text-transform:uppercase;opacity:.85;">{_esc(t("Portail sécurisé", loc))}</div>
  <h1 style="margin:6px 0 0;font-size:22px;line-height:1.25;">{_esc(t("Récapitulatif 24h", loc))}</h1>
  <div style="margin-top:6px;font-size:13px;opacity:.9;">{_esc(date_label)}</div>
</td></tr>
<tr><td style="padding:16px 24px;border-bottom:1px solid #e2e8f0;color:#475569;font-size:13px;">
  {_esc(t("Fenêtre : {since} → {until}", loc, since=_fmt_dt(recap.since), until=_fmt_dt(recap.until)))}
</td></tr>
{_html_section(
    t("Domaines découverts", loc),
    hosts_html,
    subtitle=t("Toujours en file : {n}.", loc, n=recap.pending_hosts_total),
    cta_href=hosts_cta,
    cta_label=t("Voir la file", loc),
)}
{_html_section(
    t("Comptes en attente", loc),
    accounts_html,
    subtitle=t(
        "Utilisateurs SSO : {users} · Demandes d'accès : {access} · "
        "Comptes bastion : {accounts}.",
        loc,
        users=recap.pending_users_total,
        access=recap.pending_access_total,
        accounts=recap.pending_accounts_count,
    ),
    cta_href=users_cta,
    cta_label=t("Utilisateurs", loc),
)}
{_html_section(
    t("Appareils ActiveSync", loc),
    devices_html,
    subtitle=t("Toujours en file : {n}.", loc, n=recap.pending_devices_total),
    cta_href=devices_cta,
    cta_label=t("Voir la file", loc),
)}
{_html_section(
    t("Alertes (WARNING et plus)", loc),
    alerts_html,
    subtitle=t(
        "Total : {n}. Chaque lien ouvre l'entrée exacte dans les journaux.",
        loc,
        n=recap.alerts_total,
    ),
    cta_href=logs_cta,
    cta_label=t("Filtrer WARNING+", loc),
)}
{_html_section(
    t("Bannissements (24h)", loc),
    bans_html,
)}
<tr><td style="padding:20px 24px;background:#f8fafc;border-top:1px solid #e2e8f0;font-size:13px;color:#64748b;">
  {footer_links}
  <p style="margin:0;"><a href="{_esc(admin_cta)}" style="color:#0f766e;text-decoration:none;font-weight:600;">{_esc(t("Ouvrir l'admin →", loc))}</a></p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>"""


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
    locale: str | None = None,
) -> RecapSendResult:
    """Send the 24h recap when enabled (or force=True from the admin UI)."""
    loc = _loc(locale)
    row = ensure_portal_settings(db, settings)
    enabled = bool(getattr(row, "daily_recap_enabled", False))
    if not force and not enabled:
        return RecapSendResult(
            "skipped_disabled", t("Récap quotidien désactivé", loc)
        )
    if not smtp_configured(row):
        return RecapSendResult(
            "skipped_smtp",
            t("SMTP non configuré — activez-le dans Configuration", loc),
        )
    to_email = recap_recipient(row)
    if not to_email:
        return RecapSendResult(
            "skipped_no_recipient",
            t("Aucun destinataire (email récap ou expéditeur SMTP)", loc),
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
                t(
                    "Heure d'envoi non atteinte ({hour:02d}h {tz})",
                    loc,
                    hour=hour,
                    tz=RECAP_TZ_NAME,
                ),
            )
        if _already_sent_today(row, now_local):
            return RecapSendResult(
                "skipped_already", t("Récap déjà envoyé aujourd'hui", loc)
            )

    recap = build_daily_recap(db, settings, until=_as_utc(stamp))
    subject, body_text, body_html = format_recap_email(recap, locale=loc)
    try:
        send_email(
            row,
            settings,
            to_email=to_email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            locale=loc,
        )
    except SmtpError as exc:
        log_action(
            db,
            actor=actor,
            action="portal_settings.daily_recap_failed",
            target="portal_settings",
            details={
                "ok": False,
                "error": str(exc),
                "to": to_email,
                "smtp_code": getattr(exc, "smtp_code", None),
                "smtp_detail": getattr(exc, "smtp_detail", None),
                "from": (row.smtp_from_email or "").strip() or None,
            },
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
    return RecapSendResult(
        "sent", t("Récap envoyé à {to_email}", loc, to_email=to_email)
    )


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
