"""First-login queue — mirror of pending hosts for new SSO identities."""

from __future__ import annotations

import re
from datetime import timedelta, timezone

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import AccessGrant, ActiveSession, BastionAccount, PendingUser, utcnow
from app.web.user_context import is_breakglass_email

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)

_PROTOCOL_BREAKGLASS = "BREAKGLASS"


def _aware(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _looks_like_email(value: str | None) -> bool:
    text = (value or "").strip()
    return bool(text) and "@" in text


def _looks_like_uuid(value: str | None) -> bool:
    return bool(value and _UUID_RE.match(value.strip()))


def resolve_canonical_email(
    db: Session,
    *,
    user_email: str | None,
    username: str | None = None,
) -> str | None:
    """Prefer a real email as the pending_users key; never keep a bare Keycloak UUID."""
    raw = (user_email or "").strip().lower()
    uname = (username or "").strip().lower() or None
    if _looks_like_email(raw):
        return raw
    if not raw and not uname:
        return None

    # UUID / short username in session registry → find sibling email row
    clauses = []
    if uname:
        clauses.append(ActiveSession.username == uname)
        # preferred_username sometimes equals local-part
        clauses.append(ActiveSession.user_email == uname)
    if raw and _looks_like_uuid(raw):
        clauses.append(ActiveSession.user_email == raw)
    if clauses:
        for row in (
            db.query(ActiveSession)
            .filter(or_(*clauses))
            .order_by(ActiveSession.last_seen_at.desc())
            .limit(50)
            .all()
        ):
            if _looks_like_email(row.user_email):
                return row.user_email.strip().lower()

    account_filters = []
    if uname:
        account_filters.append(func.lower(BastionAccount.username) == uname)
        account_filters.append(func.lower(BastionAccount.email) == uname)
    if raw and _looks_like_uuid(raw):
        account_filters.append(BastionAccount.keycloak_user_id == raw)
    if _looks_like_email(raw):
        account_filters.append(func.lower(BastionAccount.email) == raw)
    if account_filters:
        acc = db.query(BastionAccount).filter(or_(*account_filters)).first()
        if acc and _looks_like_email(acc.email):
            return acc.email.strip().lower()

    # Opaque id with no email — do not create a pending row
    if _looks_like_uuid(raw) or (raw and not _looks_like_email(raw)):
        return None
    return raw or None


def is_known_bastion_user(
    db: Session,
    *,
    email: str | None,
    username: str | None = None,
    keycloak_user_id: str | None = None,
) -> bool:
    """True if the identity already has Bastion authorizations or a local account."""
    em = (email or "").strip().lower() or None
    uname = (username or "").strip().lower() or None
    kc = (keycloak_user_id or "").strip() or None
    if em and _looks_like_uuid(em) and not kc:
        kc = em
        em = None

    account_filters = []
    if em:
        account_filters.append(func.lower(BastionAccount.email) == em)
    if uname:
        account_filters.append(func.lower(BastionAccount.username) == uname)
    if kc:
        account_filters.append(BastionAccount.keycloak_user_id == kc)
    if account_filters and db.query(BastionAccount.id).filter(or_(*account_filters)).first():
        return True

    grant_q = db.query(AccessGrant).filter(AccessGrant.subject_type == "user")
    if kc:
        if grant_q.filter(AccessGrant.keycloak_user_id == kc).first():
            return True
    grants = grant_q.limit(500).all()
    for g in grants:
        disp = (g.user_display_cache or "").strip().lower()
        if em and disp == em:
            return True
        if uname and (disp == uname or disp.startswith(uname + "@")):
            return True
        if em and disp and em.split("@", 1)[0] == disp:
            return True
        if kc and (g.keycloak_user_id or "") == kc:
            return True
    return False


def prune_spurious_pending_users(db: Session) -> int:
    """Drop UUID duplicates and auto-clear pending rows already known in Bastion.

    Returns number of rows removed or auto-approved.
    """
    changed = 0
    now = utcnow()
    pending = db.query(PendingUser).filter_by(status="pending").all()
    email_by_username: dict[str, PendingUser] = {}
    for row in pending:
        if _looks_like_email(row.user_email):
            key = (row.username or row.user_email.split("@", 1)[0] or "").strip().lower()
            if key:
                email_by_username[key] = row

    for row in list(pending):
        uname = (row.username or "").strip().lower() or None
        raw = (row.user_email or "").strip().lower()

        # Break-glass is local emergency auth — never an SSO first-login candidate.
        if is_breakglass_email(raw):
            db.delete(row)
            changed += 1
            continue

        canonical = resolve_canonical_email(db, user_email=raw, username=uname)

        # Bare UUID / non-email duplicate of an email row → delete
        if not _looks_like_email(raw):
            sibling = email_by_username.get(uname or "")
            if sibling is not None and sibling.id != row.id:
                db.delete(row)
                changed += 1
                continue
            if canonical and canonical != raw:
                # Re-key onto email if free; else drop
                other = db.query(PendingUser).filter_by(user_email=canonical).first()
                if other is not None:
                    db.delete(row)
                    changed += 1
                    continue
                row.user_email = canonical
                row.updated_at = now
                changed += 1
                raw = canonical
            else:
                # Cannot resolve — drop opaque pending noise
                db.delete(row)
                changed += 1
                continue

        if is_known_bastion_user(db, email=raw, username=uname, keycloak_user_id=None):
            row.status = "approved"
            row.reviewed_by = "system"
            row.reviewed_at = now
            row.notes = (row.notes or "") or "auto: déjà connu dans Bastion (droits / compte)"
            row.updated_at = now
            changed += 1
    return changed


def record_first_login_if_new(
    db: Session,
    *,
    user_email: str,
    username: str | None,
    realm_slug: str,
    source_ip: str | None,
    is_new_session_row: bool = False,
) -> PendingUser | None:
    """Create/refresh a pending row for a first-time SSO identity.

    Does not block SSO. Skips identities already known in Bastion and non-email keys.
    """
    uname = (username or "").strip() or None
    email = resolve_canonical_email(db, user_email=user_email, username=uname)
    if not email:
        return None
    if is_breakglass_email(email):
        return None
    if is_known_bastion_user(db, email=email, username=uname):
        return None

    realm = (realm_slug or "").strip() or "unknown"
    now = utcnow()

    existing = db.query(PendingUser).filter_by(user_email=email).first()
    if existing is not None:
        if existing.status != "pending":
            return None
        existing.last_seen_at = now
        existing.hit_count = int(existing.hit_count or 0) + 1
        if source_ip:
            existing.last_client_ip = source_ip
        if uname:
            existing.username = uname
        if realm:
            existing.realm_slug = realm
        existing.updated_at = now
        return existing

    if not is_new_session_row:
        return None

    # Count sessions for this email OR username-linked ids (avoid false "first" on uuid twin)
    session_emails = {email}
    if uname:
        for s in (
            db.query(ActiveSession.user_email)
            .filter(func.lower(ActiveSession.username) == uname.lower())
            .all()
        ):
            if s[0]:
                session_emails.add(s[0].strip().lower())
    session_count = (
        db.query(ActiveSession)
        .filter(ActiveSession.user_email.in_(sorted(session_emails)))
        .count()
    )
    if session_count > 1:
        return None

    row = PendingUser(
        user_email=email,
        username=(uname or email.split("@", 1)[0] or email),
        realm_slug=realm,
        first_seen_at=now,
        last_seen_at=now,
        hit_count=1,
        last_client_ip=source_ip,
        status="pending",
        updated_at=now,
    )
    db.add(row)
    return row


def discover_recent_first_logins(db: Session, *, within_hours: int = 168) -> int:
    """Backfill pending rows for identities whose earliest session is recent.

    Dedupes email vs UUID, skips Bastion-known users. Returns rows created.
    """
    prune_spurious_pending_users(db)

    cutoff = utcnow() - timedelta(hours=max(1, within_hours))
    known = {
        r[0]
        for r in db.query(PendingUser.user_email).all()
        if r[0]
    }
    rows = (
        db.query(
            ActiveSession.user_email,
            ActiveSession.username,
            func.min(ActiveSession.started_at).label("first_at"),
            func.max(ActiveSession.last_seen_at).label("last_at"),
        )
        .group_by(ActiveSession.user_email, ActiveSession.username)
        .all()
    )
    created = 0
    now = utcnow()
    seen_canonical: set[str] = set(known)

    for raw_email, username, first_at, last_at in rows:
        first_at = _aware(first_at)
        last_at = _aware(last_at)
        if first_at is None or first_at < cutoff:
            continue
        uname = (username or "").strip() or None
        email = resolve_canonical_email(db, user_email=raw_email, username=uname)
        if not email or email in seen_canonical:
            continue
        if is_breakglass_email(email):
            seen_canonical.add(email)
            continue
        if is_known_bastion_user(db, email=email, username=uname):
            seen_canonical.add(email)
            continue

        sample = (
            db.query(ActiveSession)
            .filter(ActiveSession.user_email == raw_email)
            .order_by(ActiveSession.last_seen_at.desc())
            .first()
        )
        if sample is not None and (sample.protocol or "").upper() == _PROTOCOL_BREAKGLASS:
            seen_canonical.add(email)
            continue
        db.add(
            PendingUser(
                user_email=email,
                username=(uname or email.split("@", 1)[0] or email),
                realm_slug=(sample.realm if sample else "unknown") or "unknown",
                first_seen_at=first_at,
                last_seen_at=last_at or first_at,
                hit_count=1,
                last_client_ip=sample.source_ip if sample else None,
                status="pending",
                updated_at=now,
            )
        )
        seen_canonical.add(email)
        created += 1
    return created


def acknowledge_pending_user(
    db: Session,
    *,
    user_id: int,
    actor: str,
    status: str,
    notes: str | None = None,
) -> PendingUser:
    if status not in {"approved", "rejected"}:
        raise ValueError("status must be approved or rejected")
    row = db.query(PendingUser).filter_by(id=user_id).first()
    if row is None:
        raise LookupError("pending user not found")
    now = utcnow()
    row.status = status
    row.reviewed_by = actor
    row.reviewed_at = now
    row.updated_at = now
    if notes is not None:
        row.notes = notes
    log_action(
        db,
        actor=actor,
        action=f"pending_user.{status}",
        target=row.user_email,
        details={"realm": row.realm_slug, "id": row.id},
    )
    return row
