"""Central anti-abuse engine: counters, allowlist, bans, login evaluation."""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Deque

from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import (
    SecurityAllowlistEntry,
    SecurityBan,
    SecurityBanRule,
    SecurityPolicy,
    utcnow,
)

logger = logging.getLogger(__name__)

RULE_HAMMERING = "hammering"
RULE_FAILED_LOGIN = "failed_login"
RULE_HACK_USERNAME = "hack_username"
RULE_CONCURRENT = "concurrent_connections"

TARGET_IP = "ip"
TARGET_USERNAME = "username"

DEFAULT_RULES: dict[str, dict] = {
    RULE_HAMMERING: {
        "threshold": 100,
        "window_seconds": 100,
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
}

_SENSITIVE_PREFIXES = (
    "/auth/login",
    "/auth/setup",
    "/admin",
    "/api/admin",
)

_LOGIN_PATHS = {
    "/auth/login",
    "/api/admin/breakglass/login",
}

_counter_lock = threading.Lock()
_counters: dict[tuple[str, str], Deque[float]] = defaultdict(deque)
_concurrent: dict[str, int] = defaultdict(int)


def clear_counters_for_tests() -> None:
    with _counter_lock:
        _counters.clear()
        _concurrent.clear()


def is_sensitive_path(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") or path.startswith(p + "?") for p in _SENSITIVE_PREFIXES) or path in _LOGIN_PATHS


def is_login_path(path: str, method: str = "GET") -> bool:
    if method.upper() != "POST":
        return False
    return path.rstrip("/") in _LOGIN_PATHS or path.startswith("/api/admin/breakglass/login")


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
                enabled=True,
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
    for ban in q.all():
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


def _prune_and_count(kind: str, key: str, window_seconds: int) -> int:
    now = time.monotonic()
    with _counter_lock:
        q = _counters[(kind, key)]
        cutoff = now - max(1, window_seconds)
        while q and q[0] < cutoff:
            q.popleft()
        q.append(now)
        return len(q)


def record_sensitive_request(
    db: Session,
    *,
    ip: str,
    path: str,
    method: str = "GET",
) -> SecurityBan | None:
    """Record hammering / concurrent counters; may apply a ban."""
    policy = get_policy(db)
    if not policy.enabled:
        return None
    if not ip or is_allowlisted(db, ip=ip):
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

    hammer = get_rule(db, RULE_HAMMERING)
    if not hammer or not hammer.enabled or int(hammer.threshold or 0) <= 0:
        return None

    count = _prune_and_count("hammer", ip, int(hammer.window_seconds or 1))
    if count < int(hammer.threshold):
        return None

    return apply_ban(
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

    # Failed login counters (IP + username).
    fail_rule = get_rule(db, RULE_FAILED_LOGIN)
    if not fail_rule or not fail_rule.enabled or int(fail_rule.threshold or 0) <= 0:
        return LoginEvalResult(allowed=True)

    window = int(fail_rule.window_seconds or 1)
    threshold = int(fail_rule.threshold)
    ban: SecurityBan | None = None

    if ip:
        ip_count = _prune_and_count("fail_ip", ip, window)
        if ip_count >= threshold:
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

    cfg = fail_rule.config_json or {}
    if uname and cfg.get("ban_username", True):
        user_count = _prune_and_count("fail_user", uname, window)
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

    if ban is not None:
        return LoginEvalResult(allowed=False, ban=ban, detail="failed_login_threshold")
    return LoginEvalResult(allowed=True)


def check_request_allowed(
    db: Session,
    *,
    ip: str,
    path: str,
    method: str = "GET",
) -> tuple[bool, str, SecurityBan | None]:
    """
    Pre-handler gate for sensitive paths.
    Returns (allowed, reason, ban).
    """
    policy = get_policy(db)
    if not policy.enabled or not is_sensitive_path(path):
        return True, "", None

    if is_allowlisted(db, ip=ip):
        return True, "", None

    ban = find_active_ban(db, ip=ip)
    if ban is not None:
        return False, "banned", ban

    if concurrent_limit_exceeded(db, ip):
        return False, "concurrent_limit", None

    new_ban = record_sensitive_request(db, ip=ip, path=path, method=method)
    if new_ban is not None:
        return False, "hammering", new_ban

    # Re-check in case hammering just applied.
    ban = find_active_ban(db, ip=ip)
    if ban is not None:
        return False, "banned", ban

    return True, "", None
