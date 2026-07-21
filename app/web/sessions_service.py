"""Active sessions registry — portal SSO + application launches."""

from __future__ import annotations

import logging
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import get_db
from app.models import ActiveSession, App, utcnow
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings
from app.web.user_context import UserContext, is_portal_admin, require_admin, require_user

logger = logging.getLogger(__name__)

SESSION_IDLE_TTL = timedelta(hours=8)

KIND_USER = "user"
KIND_APP = "app"

_ACCESS_MODE_PROTOCOL: dict[str, str] = {
    "sso_gate": "HTTPS",
    "subdomain_proxy": "HTTPS",
    "legacy_path_proxy": "HTTPS",
}

_PORTAL_COOKIE_HINTS = ("_oauth2_proxy", "oauth2_proxy")


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


def _merge_details(
    existing: dict[str, Any] | None,
    incoming: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not existing and not incoming:
        return None
    out = dict(existing or {})
    if incoming:
        out.update(incoming)
    return out


def portal_cookie_diagnostics(request: Request | None) -> dict[str, Any]:
    """Presence of oauth2-proxy / realm cookies on the current request."""
    if request is None:
        return {}
    present = [
        name
        for name in request.cookies.keys()
        if any(hint in name for hint in _PORTAL_COOKIE_HINTS)
        or name in ("portal_realm_slug", "csrf_token")
    ]
    oauth_present = [n for n in present if any(h in n for h in _PORTAL_COOKIE_HINTS)]
    return {
        "cookies_present": present,
        "cookies_ok": bool(oauth_present),
        "cookies_checked_at": utcnow().isoformat(),
    }


def app_cookie_diagnostics(
    cookies: dict[str, str] | None,
    *,
    credential_source: str | None = None,
    robotic_username: str | None = None,
    driver: str | None = None,
) -> dict[str, Any]:
    """Store robotic cookie presence + fingerprints after a successful impersonate."""
    from app.robotic.impersonate_service import cookie_fingerprint

    cookies = cookies or {}
    present = list(cookies.keys())
    issued_at = utcnow().isoformat()
    crush_age: str | None = None
    crush = cookies.get("CrushAuth") or ""
    # CrushAuth often starts with epoch-ms before '_'
    if crush and crush[0].isdigit():
        try:
            ms = int(crush.split("_", 1)[0])
            if ms > 1_000_000_000_000:
                issued = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
                crush_age = _format_duration(issued, utcnow())
        except (ValueError, OverflowError, OSError):
            crush_age = None
    return {
        "cookies_present": present,
        "cookies_fingerprint": cookie_fingerprint(cookies) if cookies else {},
        "cookies_ok": bool(present),
        "cookies_issued_at": issued_at,
        "crushauth_age": crush_age,
        "credential_source": credential_source,
        "robotic_username": robotic_username,
        "driver": driver,
    }


def _diagnostics_summary(details: dict[str, Any] | None) -> dict[str, Any]:
    details = details or {}
    present = details.get("cookies_present") or []
    ok = details.get("cookies_ok")
    if ok is None:
        ok = bool(present)
    label_parts: list[str] = []
    if present:
        label_parts.append(", ".join(present[:4]))
        if len(present) > 4:
            label_parts[-1] += f" (+{len(present) - 4})"
    elif ok is False:
        label_parts.append("aucun")
    else:
        label_parts.append("—")
    issued = details.get("cookies_issued_at")
    age = details.get("crushauth_age")
    validity = "ok" if ok else ("missing" if present == [] or ok is False else "unknown")
    return {
        "cookies_label": label_parts[0] if label_parts else "—",
        "cookies_ok": bool(ok),
        "cookies_validity": validity,
        "cookies_issued_at": issued,
        "crushauth_age": age,
        "credential_source": details.get("credential_source"),
        "robotic_username": details.get("robotic_username"),
    }


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
    *,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
) -> ActiveSession | None:
    """Upsert a portal (SSO / break-glass) user session. Never raises to callers."""
    try:
        merged = _merge_details(details, portal_cookie_diagnostics(request) if request else None)
        return _touch_portal_session(db, user, source_ip, details=merged)
    except Exception:
        logger.exception("touch_portal_session failed — page continues without registry")
        try:
            db.rollback()
        except Exception:
            pass
        return None


def _touch_portal_session(
    db: Session,
    user: UserContext,
    source_ip: str | None,
    *,
    details: dict[str, Any] | None = None,
) -> ActiveSession:
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
            details=details,
        )
        db.add(row)
    else:
        row.username = user.username or email
        row.protocol = _protocol_for_user(user)
        row.source_ip = source_ip or row.source_ip
        row.last_seen_at = now
        if details:
            row.details = _merge_details(row.details if isinstance(row.details, dict) else None, details)
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
    *,
    details: dict[str, Any] | None = None,
) -> ActiveSession | None:
    """Upsert an application session after launch-ping / impersonate. Never raises."""
    try:
        return _touch_app_session(db, user, app, source_ip, details=details)
    except Exception:
        logger.exception("touch_app_session failed — launch continues without registry")
        try:
            db.rollback()
        except Exception:
            pass
        return None


def _touch_app_session(
    db: Session,
    user: UserContext,
    app: App,
    source_ip: str | None,
    *,
    details: dict[str, Any] | None = None,
) -> ActiveSession:
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
            details=details,
        )
        db.add(row)
    else:
        if row.status != "isolated":
            row.status = "active"
            row.protocol = _protocol_for_app(app)
            row.username = user.username or email
        row.source_ip = source_ip or row.source_ip
        row.last_seen_at = now
        if details:
            row.details = _merge_details(row.details if isinstance(row.details, dict) else None, details)
    db.commit()
    db.refresh(row)
    return row


def _row_to_dict(row: ActiveSession) -> dict[str, Any]:
    details = row.details if isinstance(row.details, dict) else None
    diag = _diagnostics_summary(details)
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
        "details": details or {},
        "cookies_label": diag["cookies_label"],
        "cookies_ok": diag["cookies_ok"],
        "cookies_validity": diag["cookies_validity"],
        "cookies_issued_at": diag["cookies_issued_at"],
        "crushauth_age": diag["crushauth_age"],
        "credential_source": diag["credential_source"],
        "robotic_username": diag["robotic_username"],
    }


def group_sessions_by_user(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge flat sessions into one group per (user_email, realm) for UI readability."""
    groups: OrderedDict[tuple[str, str], dict[str, Any]] = OrderedDict()
    for s in sessions:
        key = (s.get("user_email") or s.get("user") or "unknown", s.get("realm") or "")
        if key not in groups:
            groups[key] = {
                "user": s.get("user") or key[0],
                "user_email": key[0],
                "realm": key[1],
                "source_ip": s.get("source_ip") or "—",
                "status": s.get("status") or "active",
                "duration": s.get("duration") or "—",
                "session_count": 0,
                "sessions": [],
            }
        g = groups[key]
        g["sessions"].append(s)
        g["session_count"] = len(g["sessions"])
        # Prefer portal IP, else first non-empty / non-dash
        if s.get("kind") == KIND_USER and s.get("source_ip") not in (None, "", "—"):
            g["source_ip"] = s["source_ip"]
        elif g["source_ip"] in (None, "", "—") and s.get("source_ip") not in (None, "", "—"):
            g["source_ip"] = s["source_ip"]
        if s.get("status") == "isolated":
            g["status"] = "isolated"
        # Longest duration among members (string compare is weak; use portal duration as headline)
        if s.get("kind") == KIND_USER:
            g["duration"] = s.get("duration") or g["duration"]
            g["user"] = s.get("user") or g["user"]
    return list(groups.values())


def get_active_sessions(
    db: Session,
    *,
    viewer: UserContext | None = None,
    kind: str | None = None,
    include_isolated: bool = True,
) -> list[dict[str, Any]]:
    """List sessions visible to viewer (admin = all, else own email)."""
    try:
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
    except Exception:
        logger.exception("get_active_sessions failed")
        try:
            db.rollback()
        except Exception:
            pass
        return []


def count_active_sessions(db: Session) -> int:
    try:
        expire_stale_sessions(db)
        return (
            db.query(ActiveSession)
            .filter(ActiveSession.status == "active")
            .count()
        )
    except Exception:
        logger.exception("count_active_sessions failed")
        try:
            db.rollback()
        except Exception:
            pass
        return 0


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
        "groups": group_sessions_by_user(sessions),
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
        ip_address=client_ip_from_request(request),
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
        ip_address=client_ip_from_request(request),
    )
    return {"status": "ok", "session_id": session_id}
