"""CRUD helpers for security banning admin UI."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import (
    SecurityAllowlistEntry,
    SecurityBan,
    SecurityBanRule,
    SecurityPolicy,
    utcnow,
)
from app.security.banning.engine import (
    TARGET_IP,
    TARGET_USERNAME,
    apply_ban,
    clear_failed_login_counters,
    ensure_security_defaults,
    get_policy,
    _normalize_username,
)


def get_or_create_policy(db: Session) -> SecurityPolicy:
    return get_policy(db)


def list_active_bans(db: Session) -> list[SecurityBan]:
    ensure_security_defaults(db)
    from app.security.banning.engine import lift_expired_bans

    lift_expired_bans(db)
    return (
        db.query(SecurityBan)
        .filter(SecurityBan.lifted_at.is_(None))
        .order_by(SecurityBan.banned_at.desc())
        .all()
    )


def list_allowlist(db: Session) -> list[SecurityAllowlistEntry]:
    ensure_security_defaults(db)
    return (
        db.query(SecurityAllowlistEntry)
        .order_by(SecurityAllowlistEntry.entry_type, SecurityAllowlistEntry.value)
        .all()
    )


def list_ban_rules(db: Session) -> list[SecurityBanRule]:
    ensure_security_defaults(db)
    return db.query(SecurityBanRule).order_by(SecurityBanRule.rule_type).all()


def update_policy_misc(
    db: Session,
    *,
    enabled: bool,
    breakglass_allow_cidrs: str,
    breakglass_deny_cidrs: str,
    actor: str,
    ip_address: str | None = None,
) -> SecurityPolicy:
    policy = get_policy(db)
    policy.enabled = bool(enabled)
    policy.breakglass_allow_cidrs = (breakglass_allow_cidrs or "").strip()
    policy.breakglass_deny_cidrs = (breakglass_deny_cidrs or "").strip()
    policy.updated_at = utcnow()
    policy.updated_by = actor
    db.commit()
    db.refresh(policy)
    log_action(
        db,
        actor=actor,
        action="security.policy.updated",
        target="security_policy",
        details={
            "enabled": policy.enabled,
            "breakglass_allow_cidrs": policy.breakglass_allow_cidrs,
            "breakglass_deny_cidrs": policy.breakglass_deny_cidrs,
        },
        ip_address=ip_address,
    )
    return policy


def update_ban_rules(
    db: Session,
    *,
    rules: dict[str, dict],
    actor: str,
    ip_address: str | None = None,
) -> list[SecurityBanRule]:
    """
    rules: {rule_type: {enabled, threshold, window_seconds, ban_minutes,
                        ban_permanent, confirm_permanent, usernames?, ban_username?}}
    """
    ensure_security_defaults(db)
    updated: list[SecurityBanRule] = []
    for rule_type, payload in rules.items():
        row = db.query(SecurityBanRule).filter_by(rule_type=rule_type).first()
        if row is None:
            continue
        row.enabled = bool(payload.get("enabled", row.enabled))
        if "threshold" in payload:
            row.threshold = max(0, int(payload["threshold"]))
        if "window_seconds" in payload:
            row.window_seconds = max(0, int(payload["window_seconds"]))
        if "ban_minutes" in payload:
            row.ban_minutes = max(0, int(payload["ban_minutes"]))
        want_permanent = bool(payload.get("ban_permanent", False))
        confirm = bool(payload.get("confirm_permanent", False))
        if want_permanent and not confirm:
            # Keep previous permanent flag rather than enabling without confirm.
            want_permanent = bool(row.ban_permanent)
            if not row.ban_permanent:
                want_permanent = False
        elif not want_permanent:
            want_permanent = False
        row.ban_permanent = want_permanent
        cfg = dict(row.config_json or {})
        if "usernames" in payload:
            names = payload["usernames"]
            if isinstance(names, str):
                names = [
                    _normalize_username(x)
                    for x in names.replace(";", ",").split(",")
                    if x.strip()
                ]
            cfg["usernames"] = [n for n in names if n]
        if "ban_username" in payload:
            cfg["ban_username"] = bool(payload["ban_username"])
        row.config_json = cfg or None
        row.updated_at = utcnow()
        updated.append(row)
    db.commit()
    log_action(
        db,
        actor=actor,
        action="security.ban_rules.updated",
        target="security_ban_rules",
        details={"rule_types": list(rules.keys())},
        ip_address=ip_address,
    )
    return updated


def apply_manual_ban(
    db: Session,
    *,
    target_type: str,
    target: str,
    reason: str,
    permanent: bool,
    ban_minutes: int,
    confirm_permanent: bool,
    actor: str,
    ip_address: str | None = None,
) -> SecurityBan | None:
    if target_type not in (TARGET_IP, TARGET_USERNAME):
        raise ValueError("target_type must be ip or username")
    return apply_ban(
        db,
        target_type=target_type,
        target=target.strip(),
        reason=reason.strip() or "Manual ban",
        rule_type="manual",
        permanent=permanent,
        ban_minutes=ban_minutes,
        actor=actor,
        ip_address=ip_address,
        confirm_permanent=confirm_permanent,
    )


def lift_ban(
    db: Session,
    ban_id: int,
    *,
    actor: str,
    ip_address: str | None = None,
) -> SecurityBan | None:
    ban = db.query(SecurityBan).filter_by(id=ban_id).first()
    if ban is None or ban.lifted_at is not None:
        return ban
    ban.lifted_at = utcnow()
    ban.lifted_by = actor
    db.commit()
    db.refresh(ban)

    # "Unblock" should reset login failure counters; otherwise the user can
    # be immediately re-banned due to lingering sliding-window events.
    if ban.target_type == TARGET_USERNAME:
        clear_failed_login_counters(db, usernames={ban.target})
    elif ban.target_type == TARGET_IP:
        clear_failed_login_counters(db, ips={ban.target})

    log_action(
        db,
        actor=actor,
        action="security.ban.lifted",
        target=f"{ban.target_type}:{ban.target}",
        details={"ban_id": ban.id, "manual": True, "reason": ban.reason},
        ip_address=ip_address,
    )
    return ban


def add_allowlist_entry(
    db: Session,
    *,
    entry_type: str,
    value: str,
    comment: str,
    actor: str,
    ip_address: str | None = None,
) -> SecurityAllowlistEntry:
    if entry_type not in (TARGET_IP, TARGET_USERNAME):
        raise ValueError("entry_type must be ip or username")
    raw = value.strip()
    if entry_type == TARGET_USERNAME:
        raw = _normalize_username(raw)
    if not raw:
        raise ValueError("value required")
    existing = (
        db.query(SecurityAllowlistEntry)
        .filter_by(entry_type=entry_type, value=raw)
        .first()
    )
    if existing:
        return existing
    row = SecurityAllowlistEntry(
        entry_type=entry_type,
        value=raw,
        comment=(comment or "").strip() or None,
        created_at=utcnow(),
        created_by=actor,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="security.allowlist.added",
        target=f"{entry_type}:{raw}",
        details={"comment": row.comment},
        ip_address=ip_address,
    )
    return row


def remove_allowlist_entry(
    db: Session,
    entry_id: int,
    *,
    actor: str,
    ip_address: str | None = None,
) -> None:
    row = db.query(SecurityAllowlistEntry).filter_by(id=entry_id).first()
    if row is None:
        return
    target = f"{row.entry_type}:{row.value}"
    db.delete(row)
    db.commit()
    log_action(
        db,
        actor=actor,
        action="security.allowlist.removed",
        target=target,
        ip_address=ip_address,
    )


def extend_ban_minutes(db: Session, ban: SecurityBan, minutes: int) -> SecurityBan:
    """Helper for tests / admin edit of expiry."""
    if ban.permanent:
        return ban
    base = ban.expires_at or utcnow()
    ban.expires_at = base + timedelta(minutes=max(1, minutes))
    db.commit()
    db.refresh(ban)
    return ban
