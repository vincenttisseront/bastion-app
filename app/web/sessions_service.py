"""Active sessions registry — portal SSO + application launches."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import get_db
from app.models import ActiveSession, App, utcnow
from app.sso_settings import Settings, get_settings
from app.web.user_context import UserContext, is_portal_admin, require_admin, require_user

SESSION_IDLE_TTL = timedelta(hours=8)

KIND_USER = "user"
KIND_APP = "app"

_ACCESS_MODE_PROTOCOL: dict[str, str] = {
    "sso_gate": "HTTPS",
    "subdomain_proxy": "HTTPS",
    "legacy_path_proxy": "HTTPS",
}


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _format_duration(started_at: datetime, last_seen_at: datetime | None = None) -> str:
    end = _aware(last_seen_at) or utcnow()
    start = _aware(started_at) or end
    seconds = max(0, int((end - start).total_seconds()))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def _portal_session_id(email: str, realm: str) -> str:
    return f"portal:{email.lower()}:{realm}"


def _app_session_id(email: str, slug: str) -> str:
    return f"app:{email.lower()}:{slug}"


def _protocol_for_user(user: UserContext) -> str:
    if user.is_breakglass:
        return "BREAKGLASS"
    return "OIDC"


def _protocol_for_app(app: App) -> str:
    return _ACCESS_MODE_PROTOCOL.get(app.access_mode or "sso_gate", "HTTPS")


def expire_stale_sessions(db: Session) -> int:
    """Delete active rows idle longer than SESSION_IDLE_TTL. Returns deleted count."""
    cutoff = utcnow() - SESSION_IDLE_TTL
    stale = (
        db.query(ActiveSession)
        .filter(
            ActiveSession.status == "active",
            ActiveSession.last_seen_at < cutoff,
        )
        .all()
    )
    for row in stale:
        db.delete(row)
    if stale:
        db.commit()
    return len(stale)


def touch_portal_session(
    db: Session,
    user: UserContext,
    source_ip: str | None,
) -> ActiveSession:
    """Upsert a portal (SSO / break-glass) user session."""
    email = (user.email or user.username or "unknown").strip().lower()
    realm = user.realm_slug or "ar-systems"
    session_id = _portal_session_id(email, realm)
    now = utcnow()
    row = db.query(ActiveSession).filter_by(id=session_id).first()
    if row is None:
        row = ActiveSession(
            id=session_id,
            kind=KIND_USER,
            user_email=email,
            username=user.username or email,
            realm=realm,
            protocol=_protocol_for_user(user),
            target="portal",
            source_ip=source_ip,
            status="active",
            started_at=now,
            last_seen_at=now,
        )
        db.add(row)
    else:
        row.username = user.username or email
        row.protocol = _protocol_for_user(user)
        row.source_ip = source_ip or row.source_ip
        row.last_seen_at = now
        if row.status != "isolated":
            row.status = "active"
    db.commit()
    db.refresh(row)
    return row


def touch_app_session(
    db: Session,
    user: UserContext,
    app: App,
    source_ip: str | None,
) -> ActiveSession:
    """Upsert an application session after launch-ping."""
    email = (user.email or user.username or "unknown").strip().lower()
    realm = user.realm_slug or app.realm_slug or "ar-systems"
    session_id = _app_session_id(email, app.slug)
    now = utcnow()
    row = db.query(ActiveSession).filter_by(id=session_id).first()
    if row is None:
        row = ActiveSession(
            id=session_id,
            kind=KIND_APP,
            user_email=email,
            username=user.username or email,
            realm=realm,
            protocol=_protocol_for_app(app),
            target=app.slug,
            source_ip=source_ip,
            status="active",
            started_at=now,
            last_seen_at=now,
        )
        db.add(row)
    else:
        if row.status != "isolated":
            row.status = "active"
            row.protocol = _protocol_for_app(app)
            row.username = user.username or email
        row.source_ip = source_ip or row.source_ip
        row.last_seen_at = now
    db.commit()
    db.refresh(row)
    return row


def _row_to_dict(row: ActiveSession) -> dict[str, Any]:
    return {
        "id": row.id,
        "kind": row.kind,
        "user": row.username or row.user_email,
        "user_email": row.user_email,
        "realm": row.realm,
        "protocol": row.protocol,
        "target": row.target,
        "source_ip": row.source_ip or "—",
        "duration": _format_duration(row.started_at, utcnow()),
        "status": row.status,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
    }


def get_active_sessions(
    db: Session,
    *,
    viewer: UserContext | None = None,
    kind: str | None = None,
    include_isolated: bool = True,
) -> list[dict[str, Any]]:
    """List sessions visible to viewer (admin = all, else own email)."""
    expire_stale_sessions(db)
    q = db.query(ActiveSession)
    if kind in (KIND_USER, KIND_APP):
        q = q.filter(ActiveSession.kind == kind)
    if not include_isolated:
        q = q.filter(ActiveSession.status == "active")
    if viewer is not None and not viewer.is_admin:
        email = (viewer.email or viewer.username or "").strip().lower()
        q = q.filter(ActiveSession.user_email == email)
    rows = q.order_by(ActiveSession.last_seen_at.desc()).all()
    return [_row_to_dict(r) for r in rows]


def count_active_sessions(db: Session) -> int:
    expire_stale_sessions(db)
    return (
        db.query(ActiveSession)
        .filter(ActiveSession.status == "active")
        .count()
    )


def get_session_by_id(db: Session, session_id: str) -> ActiveSession | None:
    return db.query(ActiveSession).filter_by(id=session_id).first()


router = APIRouter(tags=["sessions"])


@router.get("/api/sessions")
def list_sessions(
    request: Request,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_user),
    settings: Settings = Depends(get_settings),
    kind: str | None = Query(None),
):
    if is_portal_admin(user, db, settings):
        user.is_admin = True
    sessions = get_active_sessions(db, viewer=user, kind=kind)
    return {
        "sessions": sessions,
        "counts": {
            "all": len(get_active_sessions(db, viewer=user)),
            "user": len(get_active_sessions(db, viewer=user, kind=KIND_USER)),
            "app": len(get_active_sessions(db, viewer=user, kind=KIND_APP)),
        },
    }


@router.post("/admin/sessions/{session_id}/isolate")
def isolate_session(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_admin),
):
    session = get_session_by_id(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    session.status = "isolated"
    db.commit()
    log_action(
        db,
        actor=user.email,
        action="session.isolated",
        target=session.target,
        details={"session_id": session_id, "kind": session.kind},
        ip_address=request.headers.get("X-Real-IP"),
    )
    return {"status": "ok", "session_id": session_id}


@router.post("/admin/sessions/{session_id}/rotate-keys")
def rotate_keys(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_admin),
):
    session = get_session_by_id(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    log_action(
        db,
        actor=user.email,
        action="session.rotate_keys",
        target=session.target,
        details={"session_id": session_id, "kind": session.kind},
        ip_address=request.headers.get("X-Real-IP"),
    )
    return {"status": "ok", "session_id": session_id}
