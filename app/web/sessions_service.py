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
from app.request_client_ip import client_ip_from_request, client_ip_probe, is_infra_hop, prefer_client_ip
from app.sso_settings import Settings, get_settings
from app.user_agent_label import summarize_user_agent
from app.web.user_context import UserContext, is_portal_admin, require_admin, require_user

logger = logging.getLogger(__name__)

# Registry TTLs for /sessions (ActiveSession rows). Independent of browser cookies but
# should stay aligned so the UI does not show "ghost" sessions after auth is dead.
SESSION_IDLE_TTL = timedelta(hours=8)  # OIDC / app: idle since last_seen
SESSION_ABSOLUTE_TTL = timedelta(hours=12)  # OIDC: hard wall from started_at (≈ cookie_expire)
BREAKGLASS_IDLE_TTL = timedelta(minutes=30)  # match breakglass IDLE_TIMEOUT_SECONDS
BREAKGLASS_ABSOLUTE_TTL = timedelta(hours=8)  # match breakglass COOKIE_MAX_AGE

KIND_USER = "user"
KIND_APP = "app"

_PROTOCOL_BREAKGLASS = "BREAKGLASS"

_ACCESS_MODE_PROTOCOL: dict[str, str] = {
    "sso_gate": "HTTPS",
    "subdomain_proxy": "HTTPS",
    "legacy_path_proxy": "HTTPS",
}

_PORTAL_COOKIE_HINTS = ("_oauth2_proxy", "oauth2_proxy")

_ACTION_TITLES = {
    "revoke": "Révoquer : supprime la session du registre bastion et invalide les cookies stockés.",
    "rotate": "Rotation : lance le renouvellement des secrets/clés liés à cette session.",
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


def _format_last_seen(last_seen_at: datetime | None) -> str:
    dt = _aware(last_seen_at)
    if dt is None:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _relative_ago(last_seen_at: datetime | None) -> str:
    dt = _aware(last_seen_at)
    if dt is None:
        return "—"
    seconds = max(0, int((utcnow() - dt).total_seconds()))
    if seconds < 60:
        return f"il y a {seconds}s"
    if seconds < 3600:
        return f"il y a {seconds // 60} min"
    if seconds < 86400:
        return f"il y a {seconds // 3600} h"
    return f"il y a {seconds // 86400} j"


def request_client_diagnostics(request: Request | None) -> dict[str, Any]:
    """User-Agent (+ label) captured on each touch."""
    if request is None:
        return {}
    ua = (request.headers.get("User-Agent") or "").strip()
    if not ua:
        # Some proxies forward the original UA under alternate headers.
        for header in ("X-Original-User-Agent", "X-Forwarded-User-Agent"):
            ua = (request.headers.get(header) or "").strip()
            if ua:
                break
    if not ua:
        return {}
    return {
        "user_agent": ua[:500],
        "user_agent_label": summarize_user_agent(ua),
        "browser_note": None,
    }


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
    out: dict[str, Any] = {
        "cookies_present": present,
        "cookies_ok": bool(oauth_present),
        "cookies_checked_at": utcnow().isoformat(),
    }
    ua = request_client_diagnostics(request)
    if ua:
        out.update(ua)
    else:
        out["user_agent_label"] = "Non capturé"
        out["browser_note"] = (
            "User-Agent absent sur la requête (proxy / client). "
            "Rechargez /apps depuis le navigateur après déploiement."
        )
    return out


def _portal_session_id(email: str, realm: str) -> str:
    return f"portal:{email.lower()}:{realm}"


def _app_session_id(email: str, slug: str) -> str:
    return f"app:{email.lower()}:{slug}"


def _protocol_for_user(user: UserContext) -> str:
    if user.is_breakglass:
        return _PROTOCOL_BREAKGLASS
    return "OIDC"


def _looks_like_email(value: str | None) -> bool:
    text = (value or "").strip()
    return bool(text) and "@" in text


def _heal_short_session_emails(
    db: Session,
    *,
    full_email: str,
    username: str | None,
) -> None:
    """Rewrite registry rows that stored preferred_username as user_email (Hervé case)."""
    if not _looks_like_email(full_email):
        return
    full = full_email.strip().lower()
    shorts: set[str] = set()
    if username:
        u = username.strip().lower()
        if u and "@" not in u:
            shorts.add(u)
    local = full.split("@", 1)[0]
    if local and local != full:
        shorts.add(local)
    if not shorts:
        return
    rows = (
        db.query(ActiveSession)
        .filter(ActiveSession.user_email.in_(sorted(shorts)))
        .all()
    )
    for row in rows:
        row.user_email = full


def _protocol_for_app(app: App) -> str:
    return _ACCESS_MODE_PROTOCOL.get(app.access_mode or "sso_gate", "HTTPS")


def _merge_details(
    existing: dict[str, Any] | None,
    incoming: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not existing and not incoming:
        return None
    out = dict(existing or {})
    if not incoming:
        return out
    # Never wipe a captured User-Agent with an empty later touch.
    protected = dict(incoming)
    for key in ("user_agent", "user_agent_label"):
        if not protected.get(key) and out.get(key):
            protected.pop(key, None)
    # Keep session_cookies / verify_base_url unless explicitly replaced with non-empty
    for key in ("session_cookies", "verify_base_url"):
        if key in protected and not protected.get(key) and out.get(key):
            protected.pop(key, None)
    out.update(protected)
    return out


def app_cookie_diagnostics(
    cookies: dict[str, str] | None,
    *,
    credential_source: str | None = None,
    robotic_username: str | None = None,
    driver: str | None = None,
    request: Request | None = None,
    app_label: str | None = None,
    verify_base_url: str | None = None,
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
    out: dict[str, Any] = {
        "cookies_present": present,
        "cookies_fingerprint": cookie_fingerprint(cookies) if cookies else {},
        "cookies_ok": bool(present),
        "cookies_issued_at": issued_at,
        "crushauth_age": crush_age,
        "credential_source": credential_source,
        "robotic_username": robotic_username,
        "driver": driver,
        # Full cookie values for live getUsername verification (short-lived).
        "session_cookies": dict(cookies) if cookies else {},
        "verify_base_url": (verify_base_url or "").strip() or None,
        "verifiable": (driver or "").strip().lower() in ("crushftp", "generic_form"),
    }
    if app_label:
        out["app_label"] = app_label
    ua = request_client_diagnostics(request)
    if ua:
        out.update(ua)
        out["browser_note"] = None
    else:
        out["user_agent_label"] = "Session serveur (driver)"
        out["browser_note"] = (
            "Session créée côté bastion (robotic), sans User-Agent navigateur propre."
        )
    return out


def _diagnostics_summary(details: dict[str, Any] | None) -> dict[str, Any]:
    details = details or {}
    present = details.get("cookies_present") or []
    ok = details.get("cookies_ok")
    if ok is None:
        ok = bool(present)
    if present:
        label = ", ".join(present[:4])
        if len(present) > 4:
            label += f" (+{len(present) - 4})"
        cookie_title = "Cookies de session détectés : " + ", ".join(present)
    elif ok is False:
        label = "aucun"
        cookie_title = "Aucun cookie de session détecté pour cette ressource."
    else:
        label = "—"
        cookie_title = "Statut cookies inconnu (pas encore de diagnostic)."
    ua_label = details.get("user_agent_label")
    browser_note = details.get("browser_note")
    if not ua_label:
        if details.get("verifiable") or details.get("driver") in ("crushftp", "generic_form"):
            ua_label = "Session serveur (driver)"
            browser_note = browser_note or (
                "Session créée côté bastion, sans User-Agent navigateur propre."
            )
        elif details.get("user_agent"):
            ua_label = summarize_user_agent(details.get("user_agent"))
        else:
            ua_label = "Non capturé"
            browser_note = browser_note or "User-Agent absent sur la requête d’enregistrement."
    return {
        "cookies_label": label,
        "cookies_ok": bool(ok),
        "cookies_validity": "ok" if ok else ("missing" if not present else "unknown"),
        "cookies_title": cookie_title,
        "cookies_issued_at": details.get("cookies_issued_at"),
        "crushauth_age": details.get("crushauth_age"),
        "credential_source": details.get("credential_source"),
        "robotic_username": details.get("robotic_username"),
        "user_agent": details.get("user_agent"),
        "user_agent_label": ua_label,
        "browser_note": browser_note,
        "app_label": details.get("app_label"),
        "verifiable": bool(details.get("verifiable")),
        "driver": details.get("driver"),
    }


def _ttls_for_row(row: ActiveSession) -> tuple[timedelta, timedelta]:
    """Return (idle_ttl, absolute_ttl) for a registry row."""
    if (row.protocol or "").upper() == _PROTOCOL_BREAKGLASS:
        return BREAKGLASS_IDLE_TTL, BREAKGLASS_ABSOLUTE_TTL
    return SESSION_IDLE_TTL, SESSION_ABSOLUTE_TTL


def expire_stale_sessions(db: Session) -> int:
    """
    Delete active rows that exceeded idle or absolute TTL.
    Absolute TTL prevents duration from growing forever when last_seen keeps updating.
    """
    now = utcnow()
    stale = (
        db.query(ActiveSession)
        .filter(ActiveSession.status == "active")
        .all()
    )
    to_delete: list[ActiveSession] = []
    for row in stale:
        idle_ttl, absolute_ttl = _ttls_for_row(row)
        started = _aware(row.started_at)
        last_seen = _aware(row.last_seen_at) or started
        if started is not None and started < now - absolute_ttl:
            to_delete.append(row)
            continue
        if last_seen is not None and last_seen < now - idle_ttl:
            to_delete.append(row)
    for row in to_delete:
        db.delete(row)
    if to_delete:
        db.commit()
    return len(to_delete)


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
    if _looks_like_email(email):
        _heal_short_session_emails(db, full_email=email, username=user.username)
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
        row.user_email = email
        row.username = user.username or email
        row.protocol = _protocol_for_user(user)
        row.source_ip = prefer_client_ip(row.source_ip, source_ip)
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
    request: Request | None = None,
) -> ActiveSession | None:
    """Upsert an application session after launch-ping / impersonate. Never raises."""
    try:
        merged = dict(details or {})
        if app.label and "app_label" not in merged:
            merged["app_label"] = app.label
        if request is not None:
            merged = _merge_details(merged, request_client_diagnostics(request)) or {}
        return _touch_app_session(db, user, app, source_ip, details=merged or None)
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
    if _looks_like_email(email):
        _heal_short_session_emails(db, full_email=email, username=user.username)
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
        row.user_email = email
        if row.status != "isolated":
            row.status = "active"
            row.protocol = _protocol_for_app(app)
            row.username = user.username or email
        row.source_ip = prefer_client_ip(row.source_ip, source_ip)
        row.last_seen_at = now
        if details:
            row.details = _merge_details(row.details if isinstance(row.details, dict) else None, details)
            # New impersonate cookies invalidate prior live-check.
            if details.get("session_cookies"):
                row.last_verified_at = None
                row.last_verified_status = None
                merged = row.details if isinstance(row.details, dict) else {}
                if "consecutive_invalid_count" in merged:
                    merged = dict(merged)
                    merged["consecutive_invalid_count"] = 0
                    row.details = merged
    db.commit()
    db.refresh(row)
    return row


def _row_to_dict(row: ActiveSession) -> dict[str, Any]:
    details = row.details if isinstance(row.details, dict) else None
    diag = _diagnostics_summary(details)
    if row.kind == KIND_USER:
        resource_title = "Portail SSO"
        resource_subtitle = "Session portail"
        type_label = "Portail"
    else:
        resource_title = diag.get("app_label") or row.target
        resource_subtitle = f"slug · {row.target}"
        type_label = "Application"
    raw_ip = (row.source_ip or "").strip()
    infra = bool(raw_ip) and is_infra_hop(raw_ip)
    if not raw_ip:
        client_ip_display = "—"
        client_ip_note = None
    elif infra:
        client_ip_display = "indisponible (IP proxy)"
        client_ip_note = (
            f"Valeur capturée={raw_ip} (hop infra Traefik/docker). "
            "La vraie IP client n'a pas traversé la chaîne de proxys."
        )
    else:
        client_ip_display = raw_ip
        client_ip_note = None

    verifiable = bool(diag.get("verifiable"))
    verified_status = (row.last_verified_status or "").strip().lower() or None
    if verifiable:
        # Never show ACTIVE by default for driven sessions — only after live check.
        if verified_status == "active":
            live_status = "active"
            live_status_label = "ACTIVE"
        elif verified_status == "invalid":
            live_status = "invalid"
            live_status_label = "INVALIDE"
        else:
            live_status = "unverified"
            live_status_label = "NON VÉRIFIÉ"
    else:
        live_status = row.status if row.status != "isolated" else "isolated"
        live_status_label = (row.status or "active").upper()

    verified_ago = None
    if row.last_verified_at:
        verified_ago = _relative_ago(row.last_verified_at)

    return {
        "id": row.id,
        "kind": row.kind,
        "type_label": type_label,
        "user": row.username or row.user_email,
        "user_email": row.user_email,
        "realm": row.realm,
        "protocol": row.protocol,
        "target": row.target,
        "resource_title": resource_title,
        "resource_subtitle": resource_subtitle,
        "source_ip": raw_ip or "—",
        "client_ip": client_ip_display,
        "client_ip_raw": raw_ip or None,
        "client_ip_is_infra": infra or not raw_ip,
        "client_ip_note": client_ip_note,
        "duration": _format_duration(row.started_at, utcnow()),
        "status": row.status,
        "live_status": live_status,
        "live_status_label": live_status_label,
        "verifiable": verifiable,
        "last_verified_at": row.last_verified_at.isoformat() if row.last_verified_at else None,
        "last_verified_status": verified_status,
        "last_verified_ago": verified_ago,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "last_seen_label": _format_last_seen(row.last_seen_at),
        "last_seen_ago": _relative_ago(row.last_seen_at),
        "details": {
            k: v
            for k, v in (details or {}).items()
            if k != "session_cookies"  # never expose full cookies to the UI/API list
        },
        "cookies_label": diag["cookies_label"],
        "cookies_ok": diag["cookies_ok"],
        "cookies_validity": diag["cookies_validity"],
        "cookies_title": diag["cookies_title"],
        "cookies_issued_at": diag["cookies_issued_at"],
        "crushauth_age": diag["crushauth_age"],
        "credential_source": diag["credential_source"],
        "robotic_username": diag["robotic_username"],
        "user_agent": diag["user_agent"],
        "user_agent_label": diag["user_agent_label"],
        "browser_note": diag.get("browser_note"),
        "action_titles": _ACTION_TITLES,
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
            if s.get("user_agent_label") and s.get("user_agent_label") not in (
                "—",
                "Non capturé",
                "Session serveur (driver)",
            ):
                g["portal_user_agent_label"] = s.get("user_agent_label")
                g["portal_user_agent"] = s.get("user_agent")
    # Enrich driven sessions with portal browser when available
    for g in groups.values():
        portal_ua = g.pop("portal_user_agent_label", None)
        portal_ua_raw = g.pop("portal_user_agent", None)
        if not portal_ua:
            continue
        for s in g["sessions"]:
            if s.get("verifiable") and (
                not s.get("user_agent")
                or s.get("user_agent_label") in (None, "—", "Session serveur (driver)")
            ):
                s["user_agent_label"] = f"Navigateur portail : {portal_ua}"
                s["browser_note"] = (
                    "Session serveur (driver) ; User-Agent issu de la session portail associée."
                )
                if portal_ua_raw:
                    s["user_agent"] = portal_ua_raw
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


def revoke_active_session(
    db: Session,
    session: ActiveSession,
    *,
    actor: str | None,
    reason: str = "manual",
    ip_address: str | None = None,
    delete: bool = False,
) -> dict[str, Any]:
    """
    Shared revocation path for admin revoke, isolate, and downstream auto-close.

    delete=True removes the row (admin « Révoquer » + auto-revoke after target expired).
    delete=False marks status=isolated (POST …/isolate only).
    """
    session_id = session.id
    target = session.target
    kind = session.kind
    audit_details: dict[str, Any] = {
        "session_id": session_id,
        "kind": kind,
        "reason": reason,
    }
    if delete:
        # Drop stored robotic cookies with the row
        db.delete(session)
        action = "session.closed"
    else:
        session.status = "isolated"
        if isinstance(session.details, dict):
            cleaned = dict(session.details)
            cleaned.pop("session_cookies", None)
            cleaned["consecutive_invalid_count"] = 0
            session.details = cleaned
        action = "session.isolated"
    db.commit()
    log_action(
        db,
        actor=actor or "system",
        action=action,
        target=target,
        details=audit_details,
        ip_address=ip_address,
    )
    return {"session_id": session_id, "action": action, "reason": reason}


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
    payload: dict[str, Any] = {
        "sessions": sessions,
        "groups": group_sessions_by_user(sessions),
        "counts": {
            "all": len(get_active_sessions(db, viewer=user)),
            "user": len(get_active_sessions(db, viewer=user, kind=KIND_USER)),
            "app": len(get_active_sessions(db, viewer=user, kind=KIND_APP)),
        },
    }
    # Temporary diagnostic for IP capture (admins only) — remove once validated.
    if user.is_admin:
        payload["ip_probe"] = client_ip_probe(request)
    return payload


@router.post("/api/sessions/live-verify")
async def live_verify_sessions(
    request: Request,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_user),
    settings: Settings = Depends(get_settings),
):
    """
    Auto live-check driven app sessions for one user (selected in the rail).
    No manual button — called by the existing LIVE poller.
    """
    from app.web.session_verify import live_verify_user_sessions

    if is_portal_admin(user, db, settings):
        user.is_admin = True

    body: dict[str, Any] = {}
    try:
        body = await request.json()
    except Exception:
        body = {}
    target_email = (body.get("user_email") or "").strip().lower()
    if not target_email:
        raise HTTPException(status_code=400, detail="user_email required")
    if not user.is_admin:
        own = (user.email or user.username or "").strip().lower()
        if target_email != own:
            raise HTTPException(status_code=403, detail="Forbidden")

    verified = await live_verify_user_sessions(
        db,
        user_email=target_email,
        actor=user.email or user.username,
        ip_address=client_ip_from_request(request),
    )
    sessions = get_active_sessions(db, viewer=user)
    return {
        "verified": verified,
        "revoked": [v["id"] for v in verified if v.get("revoked")],
        "groups": group_sessions_by_user(sessions),
        "sessions": sessions,
        "counts": {
            "all": len(get_active_sessions(db, viewer=user)),
            "user": len(get_active_sessions(db, viewer=user, kind=KIND_USER)),
            "app": len(get_active_sessions(db, viewer=user, kind=KIND_APP)),
        },
    }


@router.post("/admin/sessions/{session_id}/revoke")
def revoke_session(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_admin),
):
    """Hard revoke: delete the ActiveSession row (admin « Révoquer cette session »)."""
    session = get_session_by_id(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    result = revoke_active_session(
        db,
        session,
        actor=user.email,
        reason="manual",
        ip_address=client_ip_from_request(request),
        delete=True,
    )
    return {"status": "ok", "session_id": result["session_id"], "action": result["action"]}


@router.post("/admin/sessions/{session_id}/isolate")
def isolate_session(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_admin),
):
    """Soft isolate: keep the row with status=isolated (not used by the Révoquer button)."""
    session = get_session_by_id(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    result = revoke_active_session(
        db,
        session,
        actor=user.email,
        reason="manual",
        ip_address=client_ip_from_request(request),
        delete=False,
    )
    return {"status": "ok", "session_id": result["session_id"]}


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
