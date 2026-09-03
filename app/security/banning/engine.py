"""Central anti-abuse engine: counters, allowlist, bans, login evaluation."""

from __future__ import annotations

import ipaddress
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import (
    AuditLog,
    SecurityAllowlistEntry,
    SecurityBan,
    SecurityBanRule,
    SecurityPolicy,
    SecurityRateEvent,
    utcnow,
)

logger = logging.getLogger(__name__)

RULE_HAMMERING = "hammering"
RULE_HAMMERING_LOGIN = "hammering_login"
RULE_FAILED_LOGIN = "failed_login"
RULE_SUCCESSFUL_LOGIN = "successful_login"
RULE_HACK_USERNAME = "hack_username"
RULE_CONCURRENT = "concurrent_connections"
RULE_RATE_LIMIT = "rate_limit"
RULE_RATE_LIMIT_LOGIN = "rate_limit_login"
RULE_UNKNOWN_HOST = "unknown_host_hammering"

TARGET_IP = "ip"
TARGET_USERNAME = "username"

# Same defaults as Settings.rfc1918_cidrs — used when evaluating break-glass ban exemption.
_DEFAULT_RFC1918_CIDRS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.1/32",
)

DEFAULT_RULES: dict[str, dict] = {
    RULE_HAMMERING: {
        "threshold": 100,
        "window_seconds": 100,
        "ban_minutes": 60,
        "ban_permanent": False,
        "config_json": None,
    },
    RULE_HAMMERING_LOGIN: {
        "threshold": 30,
        "window_seconds": 60,
        "ban_minutes": 60,
        "ban_permanent": False,
        "config_json": None,
    },
    RULE_FAILED_LOGIN: {
        "threshold": 15,
        "window_seconds": 300,
        "ban_minutes": 30,
        "ban_permanent": False,
        # Also ban the attempted username (independent of IP).
        "config_json": {"ban_username": True},
    },
    RULE_SUCCESSFUL_LOGIN: {
        "threshold": 20,
        "window_seconds": 300,
        "ban_minutes": 30,
        "ban_permanent": False,
        "config_json": None,
    },
    RULE_HACK_USERNAME: {
        "threshold": 1,
        "window_seconds": 0,
        "ban_minutes": 1440,
        "ban_permanent": False,
        # Omit plain "admin" — common legitimate break-glass account name.
        "config_json": {
            "usernames": ["administrator", "root"],
        },
    },
    RULE_CONCURRENT: {
        "threshold": 0,  # 0 = disabled
        "window_seconds": 0,
        "ban_minutes": 0,
        "ban_permanent": False,
        "config_json": None,
    },
    # Rate limiting — graduated response BEFORE the hammering ban: requests
    # beyond the budget get HTTP 429 for the rest of the window, no ban row.
    # 429'd clients keep feeding the hammering counters, so a client that
    # ignores 429 still ends up banned. Shipped disabled (explicit opt-in).
    RULE_RATE_LIMIT: {
        "enabled": False,
        "threshold": 120,
        "window_seconds": 60,
        "ban_minutes": 0,
        "ban_permanent": False,
        "config_json": None,
    },
    RULE_RATE_LIMIT_LOGIN: {
        "enabled": False,
        "threshold": 20,
        "window_seconds": 60,
        "ban_minutes": 0,
        "ban_permanent": False,
        "config_json": None,
    },
    RULE_UNKNOWN_HOST: {
        "enabled": True,
        "threshold": 50,
        "window_seconds": 300,
        "ban_minutes": 1440,
        "ban_permanent": False,
        "config_json": None,
    },
}

_SENSITIVE_PREFIXES = (
    "/login",
    "/auth/login",
    "/auth/breakglass",
    "/auth/setup",
    "/auth/sso-start",
    "/auth/sso-failed",
    "/auth/access-request",
    "/auth/altcha/challenge",
    "/admin",
    "/api/admin",
)

_LOGIN_PATHS = {
    "/login",
    "/auth/login",
    "/auth/breakglass",
    "/auth/sso-start",
    "/auth/sso-failed",
    "/auth/access-request",
    "/auth/altcha/challenge",
    "/api/admin/breakglass/login",
}

# Concurrent connections stay process-local (request lifetime); rate events are shared via SQL.
_counter_lock = threading.Lock()
_concurrent: dict[str, int] = defaultdict(int)


def clear_counters_for_tests(db: Session | None = None) -> None:
    with _counter_lock:
        _concurrent.clear()
    if db is not None:
        db.query(SecurityRateEvent).delete()
        db.commit()


def is_sensitive_path(path: str) -> bool:
    return any(
        path == p or path.startswith(p + "/") or path.startswith(p + "?")
        for p in _SENSITIVE_PREFIXES
    ) or path.rstrip("/") in _LOGIN_PATHS


def is_login_path(path: str, method: str = "GET") -> bool:
    """True for SSO/break-glass entry points (login hammering scope)."""
    p = path.rstrip("/")
    if p in ("/auth/sso-start", "/auth/sso-failed"):
        return True
    if method.upper() != "POST":
        return False
    return p in _LOGIN_PATHS or p.startswith("/api/admin/breakglass/login")


def ensure_security_defaults(db: Session) -> SecurityPolicy:
    """Ensure singleton policy + default rules exist."""
    policy = db.query(SecurityPolicy).filter_by(id=1).first()
    if policy is None:
        policy = SecurityPolicy(id=1, enabled=True)
        db.add(policy)
        db.flush()

    existing = {r.rule_type for r in db.query(SecurityBanRule).all()}
    now = utcnow()
    for rule_type, defaults in DEFAULT_RULES.items():
        if rule_type in existing:
            continue
        db.add(
            SecurityBanRule(
                rule_type=rule_type,
                enabled=bool(defaults.get("enabled", True)),
                threshold=int(defaults["threshold"]),
                window_seconds=int(defaults["window_seconds"]),
                ban_minutes=int(defaults["ban_minutes"]),
                ban_permanent=bool(defaults["ban_permanent"]),
                config_json=defaults.get("config_json"),
                updated_at=now,
            )
        )
    db.commit()
    db.refresh(policy)
    return policy


def get_policy(db: Session) -> SecurityPolicy:
    return ensure_security_defaults(db)


def get_rule(db: Session, rule_type: str) -> SecurityBanRule | None:
    ensure_security_defaults(db)
    return db.query(SecurityBanRule).filter_by(rule_type=rule_type).first()


def _parse_cidrs(raw: str) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for part in (raw or "").replace(";", ",").replace("\n", ",").split(","):
        token = part.strip()
        if not token:
            continue
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            logger.warning("invalid CIDR in security policy: %s", token)
    return nets


def _ip_in_cidrs(ip: str, nets: list[ipaddress._BaseNetwork]) -> bool:
    if not ip or not nets:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


def is_breakglass_ip_allowed(
    db: Session,
    client_ip: str,
    *,
    rfc1918_cidrs: list[str],
) -> bool:
    """Misc break-glass gate: deny list, optional allow list, else RFC1918."""
    policy = get_policy(db)
    deny = _parse_cidrs(policy.breakglass_deny_cidrs or "")
    if _ip_in_cidrs(client_ip, deny):
        return False
    allow = _parse_cidrs(policy.breakglass_allow_cidrs or "")
    if allow:
        return _ip_in_cidrs(client_ip, allow)
    # Default: RFC1918 (same as historical LAN gate).
    try:
        addr = ipaddress.ip_address(client_ip)
        return any(addr in ipaddress.ip_network(c, strict=False) for c in rfc1918_cidrs)
    except ValueError:
        return False


def is_breakglass_ban_exempt(db: Session, ip: str | None) -> bool:
    """Break-glass LAN / allowlisted ops IPs must not receive automatic hammering bans."""
    ip_n = (ip or "").strip()
    if not ip_n:
        return False
    if is_allowlisted(db, ip=ip_n):
        return True
    return is_breakglass_ip_allowed(
        db, ip_n, rfc1918_cidrs=list(_DEFAULT_RFC1918_CIDRS)
    )


def _auto_ip_ban_blocks_breakglass_lan(db: Session, ban: SecurityBan) -> bool:
    """True when an active IP ban should deny requests (respects break-glass exemption)."""
    if ban.target_type != TARGET_IP:
        return True
    if not is_breakglass_ban_exempt(db, ban.target):
        return True
    # Manual admin bans still apply; automatic hammering must not lock out LAN ops.
    return (ban.rule_type or "").strip().lower() == "manual"


def _normalize_username(username: str | None) -> str:
    return (username or "").strip().lower()


def is_allowlisted(
    db: Session,
    *,
    ip: str | None = None,
    username: str | None = None,
) -> bool:
    if ip:
        entries = (
            db.query(SecurityAllowlistEntry)
            .filter(SecurityAllowlistEntry.entry_type == TARGET_IP)
            .all()
        )
        for entry in entries:
            val = (entry.value or "").strip()
            if not val:
                continue
            try:
                if "/" in val:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(val, strict=False):
                        return True
                elif ip == val:
                    return True
            except ValueError:
                if ip == val:
                    return True
    uname = _normalize_username(username)
    if uname:
        row = (
            db.query(SecurityAllowlistEntry)
            .filter(
                SecurityAllowlistEntry.entry_type == TARGET_USERNAME,
                SecurityAllowlistEntry.value == uname,
            )
            .first()
        )
        if row is not None:
            return True
    return False


def lift_expired_bans(db: Session, *, actor: str = "system") -> int:
    """Mark expired non-permanent bans as lifted. Returns count lifted."""
    now = utcnow()
    q = (
        db.query(SecurityBan)
        .filter(
            SecurityBan.lifted_at.is_(None),
            SecurityBan.permanent.is_(False),
            SecurityBan.expires_at.isnot(None),
            SecurityBan.expires_at <= now,
        )
    )
    lifted = 0
    lifted_ips: set[str] = set()
    lifted_usernames: set[str] = set()
    for ban in q.all():
        if ban.target_type == TARGET_IP:
            lifted_ips.add(ban.target)
        elif ban.target_type == TARGET_USERNAME:
            lifted_usernames.add(_normalize_username(ban.target))
        ban.lifted_at = now
        ban.lifted_by = actor
        lifted += 1
        log_action(
            db,
            actor=actor,
            action="security.ban.lifted",
            target=f"{ban.target_type}:{ban.target}",
            details={
                "ban_id": ban.id,
                "reason": ban.reason,
                "auto": True,
                "rule_type": ban.rule_type,
            },
            ip_address=None,
        )
    if lifted:
        db.commit()
        # Unblock must also reset sliding-window counters, otherwise a user
        # can get re-banned immediately after the lift/expiry.
        clear_failed_login_counters(
            db,
            ips=lifted_ips or None,
            usernames=lifted_usernames or None,
        )
    return lifted


def find_active_ban(
    db: Session,
    *,
    ip: str | None = None,
    username: str | None = None,
) -> SecurityBan | None:
    lift_expired_bans(db)
    now = utcnow()
    candidates: list[SecurityBan] = []
    if ip:
        candidates.extend(
            db.query(SecurityBan)
            .filter(
                SecurityBan.target_type == TARGET_IP,
                SecurityBan.target == ip,
                SecurityBan.lifted_at.is_(None),
            )
            .all()
        )
    uname = _normalize_username(username)
    if uname:
        candidates.extend(
            db.query(SecurityBan)
            .filter(
                SecurityBan.target_type == TARGET_USERNAME,
                SecurityBan.target == uname,
                SecurityBan.lifted_at.is_(None),
            )
            .all()
        )
    for ban in candidates:
        if ban.target_type == TARGET_IP and not _auto_ip_ban_blocks_breakglass_lan(db, ban):
            continue
        if ban.permanent:
            return ban
        if ban.expires_at is None:
            # Treat as permanent for safety if flag inconsistent.
            return ban
        exp = ban.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp > now:
            return ban
    return None


def apply_ban(
    db: Session,
    *,
    target_type: str,
    target: str,
    reason: str,
    rule_type: str | None,
    permanent: bool,
    ban_minutes: int,
    actor: str = "system",
    ip_address: str | None = None,
    confirm_permanent: bool = False,
) -> SecurityBan | None:
    """Create a ban. Permanent requires confirm_permanent=True."""
    if target_type == TARGET_USERNAME:
        target = _normalize_username(target)
    if not target:
        return None

    if permanent and not confirm_permanent:
        logger.warning(
            "refusing permanent ban without explicit confirmation (target=%s)",
            target,
        )
        return None

    if is_allowlisted(
        db,
        ip=target if target_type == TARGET_IP else None,
        username=target if target_type == TARGET_USERNAME else None,
    ):
        return None

    if (
        target_type == TARGET_IP
        and actor == "system"
        and is_breakglass_ban_exempt(db, target)
    ):
        logger.info(
            "skipping automatic ban on break-glass allowed ip=%s rule=%s",
            target,
            rule_type,
        )
        return None

    existing = find_active_ban(
        db,
        ip=target if target_type == TARGET_IP else None,
        username=target if target_type == TARGET_USERNAME else None,
    )
    if existing is not None:
        return existing

    now = utcnow()
    expires_at: datetime | None = None
    if not permanent:
        minutes = max(1, int(ban_minutes or 60))
        expires_at = now + timedelta(minutes=minutes)

    ban = SecurityBan(
        target_type=target_type,
        target=target,
        reason=reason,
        rule_type=rule_type,
        banned_at=now,
        expires_at=expires_at,
        permanent=permanent,
        created_by=actor,
    )
    db.add(ban)
    db.commit()
    db.refresh(ban)
    log_action(
        db,
        actor=actor,
        action="security.ban.applied",
        target=f"{target_type}:{target}",
        details={
            "ban_id": ban.id,
            "reason": reason,
            "rule_type": rule_type,
            "permanent": permanent,
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
        ip_address=ip_address,
    )
    return ban


def clear_failed_login_counters(
    db: Session,
    *,
    ips: set[str] | None = None,
    usernames: set[str] | None = None,
) -> int:
    """Clear SQL sliding-window counters for failed logins.

    Used for "unblock" semantics after ban lift/expiry, and on successful
    login to avoid lingering failures re-triggering bans.
    """
    ips = {ip for ip in (ips or set()) if (ip or "").strip()}
    usernames = {
        _normalize_username(u)
        for u in (usernames or set())
        if (u or "").strip()
    }
    deleted = 0
    try:
        if ips:
            deleted += (
                db.query(SecurityRateEvent)
                .filter(
                    SecurityRateEvent.kind == "fail_ip",
                    SecurityRateEvent.key.in_(sorted(ips)),
                )
                .delete(synchronize_session=False)
            )
        if usernames:
            deleted += (
                db.query(SecurityRateEvent)
                .filter(
                    SecurityRateEvent.kind == "fail_user",
                    SecurityRateEvent.key.in_(sorted(usernames)),
                )
                .delete(synchronize_session=False)
            )
        if deleted:
            db.commit()
    except SQLAlchemyError:
        logger.warning("failed-login counters clear failed (rollback)")
        try:
            db.rollback()
        except SQLAlchemyError:
            logger.exception("failed-login counters clear rollback failed")
        return 0
    return deleted


def _prune_and_count(db: Session, kind: str, key: str, window_seconds: int) -> int:
    """Append a rate event and return sliding-window count (shared via SQL)."""
    key_n = (key or "").strip()[:255]
    if not key_n:
        return 0
    now = utcnow()
    cutoff = now - timedelta(seconds=max(1, int(window_seconds or 1)))
    # Prune this key's stale events (keep table small).
    (
        db.query(SecurityRateEvent)
        .filter(
            SecurityRateEvent.kind == kind,
            SecurityRateEvent.key == key_n,
            SecurityRateEvent.occurred_at < cutoff,
        )
        .delete(synchronize_session=False)
    )
    db.add(SecurityRateEvent(kind=kind, key=key_n, occurred_at=now))
    db.flush()
    return (
        db.query(SecurityRateEvent)
        .filter(
            SecurityRateEvent.kind == kind,
            SecurityRateEvent.key == key_n,
            SecurityRateEvent.occurred_at >= cutoff,
        )
        .count()
    )


def record_sensitive_request(
    db: Session,
    *,
    ip: str,
    path: str,
    method: str = "GET",
) -> SecurityBan | None:
    """Record hammering counters (all sensitive + login-only); may apply a ban."""
    policy = get_policy(db)
    if not policy.enabled:
        return None
    if not ip or is_allowlisted(db, ip=ip) or is_breakglass_ban_exempt(db, ip):
        return None

    concurrent_rule = get_rule(db, RULE_CONCURRENT)
    if (
        concurrent_rule
        and concurrent_rule.enabled
        and int(concurrent_rule.threshold or 0) > 0
    ):
        with _counter_lock:
            active = _concurrent.get(ip, 0)
        if active >= int(concurrent_rule.threshold):
            # Refuse without ban — caller should return 429/403.
            return None

    ban: SecurityBan | None = None

    hammer = get_rule(db, RULE_HAMMERING)
    if hammer and hammer.enabled and int(hammer.threshold or 0) > 0:
        count = _prune_and_count(db, "hammer", ip, int(hammer.window_seconds or 1))
        if count >= int(hammer.threshold):
            ban = apply_ban(
                db,
                target_type=TARGET_IP,
                target=ip,
                reason=f"Hammering: {count} requests in {hammer.window_seconds}s",
                rule_type=RULE_HAMMERING,
                permanent=bool(hammer.ban_permanent),
                ban_minutes=int(hammer.ban_minutes or 60),
                actor="system",
                ip_address=ip,
                confirm_permanent=bool(hammer.ban_permanent),
            )

    if is_login_path(path, method):
        login_hammer = get_rule(db, RULE_HAMMERING_LOGIN)
        if (
            login_hammer
            and login_hammer.enabled
            and int(login_hammer.threshold or 0) > 0
            and ban is None
        ):
            count = _prune_and_count(
                db, "hammer_login", ip, int(login_hammer.window_seconds or 1)
            )
            if count >= int(login_hammer.threshold):
                ban = apply_ban(
                    db,
                    target_type=TARGET_IP,
                    target=ip,
                    reason=(
                        f"Login hammering: {count} login requests "
                        f"in {login_hammer.window_seconds}s"
                    ),
                    rule_type=RULE_HAMMERING_LOGIN,
                    permanent=bool(login_hammer.ban_permanent),
                    ban_minutes=int(login_hammer.ban_minutes or 60),
                    actor="system",
                    ip_address=ip,
                    confirm_permanent=bool(login_hammer.ban_permanent),
                )

    if ban is None:
        # Persist counter events even when no ban was applied.
        try:
            db.commit()
        except Exception:
            db.rollback()
    return ban


def record_unknown_host_refusal(
    db: Session,
    *,
    ip: str,
    hostname: str | None = None,
    uri: str | None = None,
) -> SecurityBan | None:
    """Count unknown-Host refusals per IP; ban aggressive scanners (PerplexityBot, etc.)."""
    policy = get_policy(db)
    if not policy.enabled:
        return None
    ip_n = (ip or "").strip()
    if not ip_n or is_allowlisted(db, ip=ip_n) or is_breakglass_ban_exempt(db, ip_n):
        return None

    existing = find_active_ban(db, ip=ip_n)
    if existing is not None:
        return None

    rule = get_rule(db, RULE_UNKNOWN_HOST)
    if not rule or not rule.enabled or int(rule.threshold or 0) <= 0:
        return None

    count = _prune_and_count(
        db, "unknown_host", ip_n, int(rule.window_seconds or 300)
    )
    if count < int(rule.threshold):
        try:
            db.commit()
        except Exception:
            db.rollback()
        return None

    ban = apply_ban(
        db,
        target_type=TARGET_IP,
        target=ip_n,
        reason=(
            f"Unknown host hammering: {count} refusals in {rule.window_seconds}s"
        ),
        rule_type=RULE_UNKNOWN_HOST,
        permanent=bool(rule.ban_permanent),
        ban_minutes=int(rule.ban_minutes or 1440),
        actor="system",
        ip_address=ip_n,
        confirm_permanent=bool(rule.ban_permanent),
    )
    if ban is not None:
        log_action(
            db,
            actor="system",
            action="security.unknown_host_hammering.detected",
            target=f"ip:{ip_n}",
            details={
                "count": count,
                "window_seconds": int(rule.window_seconds or 300),
                "hostname": (hostname or "")[:253] or None,
                "uri": (uri or "")[:1024] or None,
                "ban_id": ban.id,
            },
            ip_address=ip_n,
        )
    return ban


def _recent_rate_limit_audit(
    db: Session, *, ip: str, rule_type: str, window: int
) -> bool:
    """True if we already wrote security.rate_limited for this IP/rule in the window."""
    cutoff = utcnow() - timedelta(seconds=max(1, int(window or 1)))
    target = f"ip:{ip}"
    rows = (
        db.query(AuditLog)
        .filter(
            AuditLog.action == "security.rate_limited",
            AuditLog.target == target,
            AuditLog.created_at >= cutoff,
        )
        .limit(20)
        .all()
    )
    for row in rows:
        details = row.details if isinstance(row.details, dict) else {}
        if details.get("rule_type") == rule_type:
            return True
    return False


def record_rate_limited_request(
    db: Session,
    *,
    ip: str,
    path: str,
    method: str = "GET",
) -> tuple[bool, int]:
    """Sliding-window rate limit (HTTP 429) — throttle, never a ban row.

    Complements the hammering rules: the throttle rejects softly at a lower
    threshold, the hammering ban stays the hard stop above it (429'd requests
    still feed the hammering counters via record_sensitive_request).
    Audit `security.rate_limited` only on the FIRST rejection of a burst so
    a hammering client cannot flood the audit log.
    Returns (limited, retry_after_seconds).
    """
    policy = get_policy(db)
    if not policy.enabled or not ip or is_allowlisted(db, ip=ip):
        return False, 0
    if is_breakglass_ban_exempt(db, ip):
        return False, 0

    checks: list[tuple[str, str]] = [(RULE_RATE_LIMIT, "rate")]
    if is_login_path(path, method):
        checks.append((RULE_RATE_LIMIT_LOGIN, "rate_login"))

    limited = False
    retry_after = 0
    for rule_type, kind in checks:
        rule = get_rule(db, rule_type)
        if not rule or not rule.enabled or int(rule.threshold or 0) <= 0:
            continue
        window = int(rule.window_seconds or 1)
        threshold = int(rule.threshold)
        count = _prune_and_count(db, kind, ip, window)
        if count <= threshold:
            continue
        limited = True
        retry_after = max(retry_after, window)
        # Audit on the first rejection of the burst (count == threshold+1). If
        # concurrent workers skip that exact count, still audit once when we
        # first observe a limited window (count just above threshold).
        should_audit = count == threshold + 1 or (
            count > threshold + 1
            and count <= threshold + 3
            and not _recent_rate_limit_audit(db, ip=ip, rule_type=rule_type, window=window)
        )
        if should_audit:
            logger.warning(
                "security.rate_limited ip=%s rule=%s count=%s/%s window=%ss path=%s",
                ip,
                rule_type,
                count,
                threshold,
                window,
                (path or "")[:120],
            )
            log_action(
                db,
                actor="system",
                action="security.rate_limited",
                target=f"ip:{ip}",
                details={
                    "rule_type": rule_type,
                    "count": count,
                    "threshold": threshold,
                    "window_seconds": window,
                    "path": (path or "")[:120],
                    "method": (method or "")[:16],
                },
                ip_address=ip,
            )

    try:
        db.commit()
    except Exception:
        db.rollback()
    return limited, retry_after


def rate_limit_retry_after(db: Session, path: str, method: str = "GET") -> int:
    """Retry-After (seconds) for a 429 — largest enabled applicable window."""
    windows = []
    rule = get_rule(db, RULE_RATE_LIMIT)
    if rule and rule.enabled:
        windows.append(int(rule.window_seconds or 60))
    if is_login_path(path, method):
        rule = get_rule(db, RULE_RATE_LIMIT_LOGIN)
        if rule and rule.enabled:
            windows.append(int(rule.window_seconds or 60))
    return max(windows) if windows else 60


def record_successful_login(
    db: Session,
    *,
    ip: str,
    username: str,
) -> SecurityBan | None:
    """
    Count successful logins from one IP; ban the username when threshold exceeded.
    """
    policy = get_policy(db)
    if not policy.enabled:
        return None
    uname = _normalize_username(username)
    if not uname or not ip:
        return None
    if is_allowlisted(db, ip=ip, username=uname):
        return None

    rule = get_rule(db, RULE_SUCCESSFUL_LOGIN)
    if not rule or not rule.enabled or int(rule.threshold or 0) <= 0:
        return None

    count = _prune_and_count(db, "success_ip", ip, int(rule.window_seconds or 1))
    if count < int(rule.threshold):
        try:
            db.commit()
        except Exception:
            db.rollback()
        return None

    ban = apply_ban(
        db,
        target_type=TARGET_USERNAME,
        target=uname,
        reason=(
            f"Successful-login hammering: {count} logins from {ip} "
            f"in {rule.window_seconds}s"
        ),
        rule_type=RULE_SUCCESSFUL_LOGIN,
        permanent=bool(rule.ban_permanent),
        ban_minutes=int(rule.ban_minutes or 30),
        actor="system",
        ip_address=ip,
        confirm_permanent=bool(rule.ban_permanent),
    )
    if ban is not None:
        log_action(
            db,
            actor=uname,
            action="security.successful_login_hammering.detected",
            target=f"username:{uname}",
            details={"ip": ip, "count": count, "window_seconds": rule.window_seconds},
            ip_address=ip or None,
        )
    return ban


def begin_concurrent(ip: str) -> None:
    if not ip:
        return
    with _counter_lock:
        _concurrent[ip] += 1


def end_concurrent(ip: str) -> None:
    if not ip:
        return
    with _counter_lock:
        _concurrent[ip] = max(0, _concurrent[ip] - 1)
        if _concurrent[ip] == 0:
            _concurrent.pop(ip, None)


def concurrent_limit_exceeded(db: Session, ip: str) -> bool:
    rule = get_rule(db, RULE_CONCURRENT)
    if not rule or not rule.enabled or int(rule.threshold or 0) <= 0:
        return False
    if is_allowlisted(db, ip=ip):
        return False
    with _counter_lock:
        return _concurrent.get(ip, 0) >= int(rule.threshold)


@dataclass
class LoginEvalResult:
    allowed: bool
    ban: SecurityBan | None = None
    hack_attempt: bool = False
    detail: str = ""


def evaluate_login_attempt(
    db: Session,
    *,
    ip: str,
    username: str,
    success: bool,
) -> LoginEvalResult:
    """Evaluate a login attempt: decoy usernames, failed-login thresholds."""
    policy = get_policy(db)
    if not policy.enabled:
        return LoginEvalResult(allowed=True)

    uname = _normalize_username(username)
    if is_allowlisted(db, ip=ip, username=uname):
        return LoginEvalResult(allowed=True)

    active = find_active_ban(db, ip=ip, username=uname)
    if active is not None:
        return LoginEvalResult(
            allowed=False,
            ban=active,
            detail="already_banned",
        )

    # Decoy / hack usernames → immediate IP ban (even before password check).
    hack_rule = get_rule(db, RULE_HACK_USERNAME)
    if hack_rule and hack_rule.enabled and uname:
        cfg = hack_rule.config_json or {}
        decoys = {
            _normalize_username(u)
            for u in (cfg.get("usernames") or [])
            if isinstance(u, str)
        }
        if uname in decoys:
            log_action(
                db,
                actor=uname,
                action="security.hack_attempt.detected",
                target=f"username:{uname}",
                details={"ip": ip},
                ip_address=ip or None,
            )
            ban = apply_ban(
                db,
                target_type=TARGET_IP,
                target=ip,
                reason=f"Hack attempt username: {uname}",
                rule_type=RULE_HACK_USERNAME,
                permanent=bool(hack_rule.ban_permanent),
                ban_minutes=int(hack_rule.ban_minutes or 1440),
                actor="system",
                ip_address=ip,
                confirm_permanent=bool(hack_rule.ban_permanent),
            )
            return LoginEvalResult(
                allowed=False,
                ban=ban,
                hack_attempt=True,
                detail="hack_username",
            )

    if success:
        return LoginEvalResult(allowed=True)

    # Failed login counters (IP + username) — shared via SQL.
    fail_rule = get_rule(db, RULE_FAILED_LOGIN)
    if not fail_rule or not fail_rule.enabled or int(fail_rule.threshold or 0) <= 0:
        return LoginEvalResult(allowed=True)

    window = int(fail_rule.window_seconds or 1)
    threshold = int(fail_rule.threshold)
    ban: SecurityBan | None = None

    cfg = fail_rule.config_json or {}
    try:
        if ip:
            ip_count = _prune_and_count(db, "fail_ip", ip, window)
            if ip_count >= threshold and not is_breakglass_ban_exempt(db, ip):
                ban = apply_ban(
                    db,
                    target_type=TARGET_IP,
                    target=ip,
                    reason=f"Failed logins: {ip_count} in {window}s",
                    rule_type=RULE_FAILED_LOGIN,
                    permanent=bool(fail_rule.ban_permanent),
                    ban_minutes=int(fail_rule.ban_minutes or 30),
                    actor="system",
                    ip_address=ip,
                    confirm_permanent=bool(fail_rule.ban_permanent),
                )

        if uname and cfg.get("ban_username", True):
            user_count = _prune_and_count(db, "fail_user", uname, window)
            if user_count >= threshold:
                ban = apply_ban(
                    db,
                    target_type=TARGET_USERNAME,
                    target=uname,
                    reason=f"Failed logins on account: {user_count} in {window}s",
                    rule_type=RULE_FAILED_LOGIN,
                    permanent=bool(fail_rule.ban_permanent),
                    ban_minutes=int(fail_rule.ban_minutes or 30),
                    actor="system",
                    ip_address=ip,
                    confirm_permanent=bool(fail_rule.ban_permanent),
                ) or ban
    except SQLAlchemyError:
        # Rate events live in the hot store. Unable to count is not "over the
        # threshold" — turning an outage into a 500 on the login form would
        # lock out the very account meant to repair it.
        logger.warning("failed-login counters unavailable, skipping ban evaluation")
        try:
            db.rollback()
        except SQLAlchemyError:
            logger.exception("rollback failed after rate store outage")
        return LoginEvalResult(allowed=True)

    if ban is not None:
        return LoginEvalResult(allowed=False, ban=ban, detail="failed_login_threshold")
    try:
        db.commit()
    except Exception:
        db.rollback()
    return LoginEvalResult(allowed=True)


def identity_username_from_headers(headers) -> str:
    """Best-effort account id from Nginx-injected identity headers."""
    try:
        email = (headers.get("X-Email") or "").strip()
        user = (headers.get("X-User") or "").strip()
        preferred = (headers.get("X-Preferred-Username") or "").strip()
    except Exception:
        return ""
    for candidate in (email, preferred, user):
        if candidate and "@" in candidate:
            return _normalize_username(candidate)
    for candidate in (preferred, user, email):
        if candidate:
            return _normalize_username(candidate)
    return ""


def check_request_allowed(
    db: Session,
    *,
    ip: str,
    path: str,
    method: str = "GET",
    username: str | None = None,
) -> tuple[bool, str, SecurityBan | None]:
    """
    Pre-handler gate for sensitive paths.
    Returns (allowed, reason, ban).
    """
    policy = get_policy(db)
    if not policy.enabled or not is_sensitive_path(path):
        return True, "", None

    uname = _normalize_username(username or "")
    if is_allowlisted(db, ip=ip, username=uname or None):
        return True, "", None

    ban = find_active_ban(db, ip=ip, username=uname or None)
    if ban is not None:
        return False, "banned", ban

    if concurrent_limit_exceeded(db, ip):
        return False, "concurrent_limit", None

    new_ban = record_sensitive_request(db, ip=ip, path=path, method=method)
    if new_ban is not None:
        return False, "hammering", new_ban

    # Re-check in case hammering just applied (IP or username).
    ban = find_active_ban(db, ip=ip, username=uname or None)
    if ban is not None:
        return False, "banned", ban

    # Throttle AFTER the hammering counters: a client that keeps pushing
    # through 429s still accumulates toward the hammering ban.
    limited, _retry = record_rate_limited_request(db, ip=ip, path=path, method=method)
    if limited:
        return False, "rate_limited", None

    return True, "", None
