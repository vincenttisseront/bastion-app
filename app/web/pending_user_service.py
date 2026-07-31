"""First-login queue — mirror of pending hosts for new SSO identities."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import ActiveSession, PendingUser, utcnow


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

    Does not block SSO. Prefer calling with ``is_new_session_row=True`` right after
    inserting the first ActiveSession for that email.
    """
    email = (user_email or "").strip().lower()
    if not email or email == "unknown":
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
        if username:
            existing.username = username
        if realm:
            existing.realm_slug = realm
        existing.updated_at = now
        return existing

    if not is_new_session_row:
        return None

    session_count = (
        db.query(ActiveSession).filter(ActiveSession.user_email == email).count()
    )
    if session_count > 1:
        return None

    row = PendingUser(
        user_email=email,
        username=(username or email).strip() or email,
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


def _aware(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        from datetime import timezone

        return dt.replace(tzinfo=timezone.utc)
    return dt


def discover_recent_first_logins(db: Session, *, within_hours: int = 168) -> int:
    """Backfill pending rows for identities whose earliest session is recent.

    Returns number of rows created. Skips emails already in pending_users.
    """
    cutoff = utcnow() - timedelta(hours=max(1, within_hours))
    known = {
        r[0]
        for r in db.query(PendingUser.user_email).all()
        if r[0]
    }
    rows = (
        db.query(
            ActiveSession.user_email,
            func.min(ActiveSession.started_at).label("first_at"),
            func.max(ActiveSession.last_seen_at).label("last_at"),
            func.count(ActiveSession.id).label("n"),
        )
        .group_by(ActiveSession.user_email)
        .all()
    )
    created = 0
    now = utcnow()
    for email, first_at, last_at, _n in rows:
        em = (email or "").strip().lower()
        if not em or em in known or em == "unknown":
            continue
        first_at = _aware(first_at)
        last_at = _aware(last_at)
        if first_at is None or first_at < cutoff:
            continue
        sample = (
            db.query(ActiveSession)
            .filter(ActiveSession.user_email == email)
            .order_by(ActiveSession.last_seen_at.desc())
            .first()
        )
        db.add(
            PendingUser(
                user_email=em,
                username=(sample.username if sample else em) or em,
                realm_slug=(sample.realm if sample else "unknown") or "unknown",
                first_seen_at=first_at,
                last_seen_at=last_at or first_at,
                hit_count=1,
                last_client_ip=sample.source_ip if sample else None,
                status="pending",
                updated_at=now,
            )
        )
        known.add(em)
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
