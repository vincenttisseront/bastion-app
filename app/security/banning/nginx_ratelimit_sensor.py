"""Nginx limit_req (HTTP 429) sensor → progressive SecurityBan auto-escalation.

Reads ``bastion-rate-limit.log`` lines produced by the WAF rate-limits overlay
(``log_format bastion_rate_limit``), records ``SecurityRateEvent(kind=nginx_429)``,
and escalates when an IP exceeds the ``nginx_limit_req`` rule threshold.
"""

from __future__ import annotations

import logging
import re
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.models import SecurityRateEvent, utcnow
from app.security.banning.engine import (
    RULE_NGINX_LIMIT_REQ,
    apply_nginx_limit_req_ban,
    ensure_security_defaults,
    get_rule,
    is_allowlisted,
    is_breakglass_ban_exempt,
)
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

KIND_NGINX_429 = "nginx_429"

# $remote_addr $time_iso8601 $request_method $uri $status $request_length
_LINE_RE = re.compile(
    r"^(?P<ip>\S+)\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<method>\S+)\s+"
    r"(?P<uri>\S+)\s+"
    r"(?P<status>\d+)\s+"
    r"(?P<length>\d+)\s*$"
)

_cursor_lock = threading.Lock()
_file_offsets: dict[str, int] = {}


def default_rate_limit_log_path(settings: Settings) -> Path:
    custom = (getattr(settings, "nginx_rate_limit_log_path", None) or "").strip()
    if custom:
        return Path(custom)
    # Prefer container path; fall back under exports for tests/dev.
    container = Path("/var/log/nginx/bastion-rate-limit.log")
    if container.is_file() or container.parent.is_dir():
        return container
    return Path(settings.exports_dir) / "bastion-rate-limit.log"


def parse_rate_limit_line(line: str) -> dict[str, Any] | None:
    text = (line or "").strip()
    if not text or text.startswith("#"):
        return None
    m = _LINE_RE.match(text)
    if not m:
        return None
    status = int(m.group("status"))
    if status != 429:
        return None
    uri = m.group("uri")
    zone = _infer_zone(uri)
    return {
        "ip": m.group("ip"),
        "method": m.group("method"),
        "uri": uri,
        "status": status,
        "zone": zone,
        "raw_ts": m.group("ts"),
    }


def _infer_zone(uri: str) -> str:
    path = (uri or "").split("?", 1)[0]
    if path.startswith("/admin/auth") or path.startswith("/auth/") or path.startswith(
        "/login"
    ):
        return "login"
    if path.startswith("/api/"):
        return "api"
    return "standard"


def record_nginx_429(
    db: Session,
    *,
    ip: str,
    zone: str | None = None,
    occurred_at: datetime | None = None,
) -> int:
    """Persist one 429 event; return count in the active rule window for this IP."""
    ensure_security_defaults(db)
    rule = get_rule(db, RULE_NGINX_LIMIT_REQ)
    window = int(rule.window_seconds if rule else 60) or 60
    ip_n = (ip or "").strip()
    if not ip_n:
        return 0
    now = occurred_at or utcnow()
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    # key encodes zone for diagnostics; counting is per-IP across zones.
    key = ip_n if not zone else f"{ip_n}|{zone}"
    db.add(SecurityRateEvent(kind=KIND_NGINX_429, key=key, occurred_at=now))
    db.flush()
    cutoff = now - timedelta(seconds=window)
    from sqlalchemy import or_

    return (
        db.query(SecurityRateEvent)
        .filter(
            SecurityRateEvent.kind == KIND_NGINX_429,
            or_(
                SecurityRateEvent.key == ip_n,
                SecurityRateEvent.key.like(f"{ip_n}|%"),
            ),
            SecurityRateEvent.occurred_at >= cutoff,
        )
        .count()
    )


def maybe_escalate_ip(
    db: Session,
    *,
    ip: str,
    count: int,
    zone: str | None = None,
    settings: Settings | None = None,
) -> Any:
    """If count >= threshold, apply progressive ban and optionally re-export deny."""
    ensure_security_defaults(db)
    rule = get_rule(db, RULE_NGINX_LIMIT_REQ)
    if rule is None or not rule.enabled:
        return None
    if count < int(rule.threshold or 30):
        return None
    ip_n = (ip or "").strip()
    if not ip_n:
        return None
    if is_allowlisted(db, ip=ip_n) or is_breakglass_ban_exempt(db, ip_n):
        return None

    ban = apply_nginx_limit_req_ban(
        db,
        ip=ip_n,
        rejection_count=count,
        window_seconds=int(rule.window_seconds or 60),
        zone=zone,
    )
    if ban is not None and settings is not None:
        try:
            from app.bastion.nginx_waf_export import write_waf_exports

            write_waf_exports(db, settings)
        except Exception:
            logger.exception("nginx rate-limit ban: deny export failed")
    return ban


def ingest_parsed_events(
    db: Session,
    events: list[dict[str, Any]],
    *,
    settings: Settings | None = None,
) -> list[Any]:
    """Record events and escalate; returns list of new bans."""
    bans: list[Any] = []
    # Aggregate per IP for this batch then escalate once.
    per_ip: dict[str, dict[str, Any]] = {}
    for ev in events:
        ip = (ev.get("ip") or "").strip()
        if not ip:
            continue
        zone = ev.get("zone")
        count = record_nginx_429(db, ip=ip, zone=zone)
        cur = per_ip.get(ip)
        if cur is None or count >= cur["count"]:
            per_ip[ip] = {"count": count, "zone": zone}
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    for ip, meta in per_ip.items():
        ban = maybe_escalate_ip(
            db,
            ip=ip,
            count=int(meta["count"]),
            zone=meta.get("zone"),
            settings=settings,
        )
        if ban is not None:
            bans.append(ban)
    return bans


def read_new_log_lines(path: Path) -> list[str]:
    """Tail unread bytes from path (per-process offset cursor)."""
    if not path.is_file():
        return []
    key = str(path.resolve()) if path.exists() else str(path)
    with _cursor_lock:
        offset = _file_offsets.get(key, 0)
        size = path.stat().st_size
        if size < offset:
            # rotated
            offset = 0
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            chunk = fh.read()
            _file_offsets[key] = fh.tell()
    if not chunk:
        return []
    return [ln for ln in chunk.splitlines() if ln.strip()]


def run_sensor_tick(db: Session, settings: Settings) -> dict[str, Any]:
    """One scheduler tick: parse new 429 log lines and escalate."""
    ensure_security_defaults(db)
    path = default_rate_limit_log_path(settings)
    lines = read_new_log_lines(path)
    events = []
    for ln in lines:
        parsed = parse_rate_limit_line(ln)
        if parsed:
            events.append(parsed)
    bans = ingest_parsed_events(db, events, settings=settings) if events else []
    return {
        "log_path": str(path),
        "lines_read": len(lines),
        "events": len(events),
        "bans": len(bans),
    }


def count_nginx_429_events_24h(db: Session) -> int:
    cutoff = utcnow() - timedelta(hours=24)
    return (
        db.query(SecurityRateEvent)
        .filter(
            SecurityRateEvent.kind == KIND_NGINX_429,
            SecurityRateEvent.occurred_at >= cutoff,
        )
        .count()
    )


def reset_sensor_cursors_for_tests() -> None:
    with _cursor_lock:
        _file_offsets.clear()
