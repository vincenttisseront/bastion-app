"""Live verification of driven (CrushFTP / generic_form) app sessions."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import httpx
from sqlalchemy.orm import Session

from app.bastion.drivers.base import RoboticLoginError
from app.bastion.drivers.crushftp import CrushFTPDriver, CrushFTPSession
from app.models import ActiveSession, utcnow
from app.web.session_cookie_seal import open_session_cookies

logger = logging.getLogger(__name__)

VerifyStatus = Literal["active", "invalid", "unknown"]

_DRIVEN_DRIVERS = frozenset({"crushftp", "generic_form"})
_VERIFY_TIMEOUT = 5.0
_INVALID_STREAK_TO_REVOKE = 2

# Background probing (live /sessions stream): each driven session is probed at
# most every PROBE_MIN_INTERVAL, whoever is watching. Two "invalid" strikes
# closer than STREAM_STRIKE_GAP count as one, so concurrent viewers / workers
# can never auto-revoke on a single upstream hiccup.
PROBE_MIN_INTERVAL = timedelta(seconds=45)
STREAM_STRIKE_GAP = timedelta(seconds=20)
_PROBE_CONCURRENCY = 4
_PROBE_BATCH = 24


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def is_driven_session(row: ActiveSession) -> bool:
    details = row.details if isinstance(row.details, dict) else {}
    driver = (details.get("driver") or "").strip().lower()
    return row.kind == "app" and driver in _DRIVEN_DRIVERS


def _details_dict(row: ActiveSession) -> dict[str, Any]:
    return dict(row.details) if isinstance(row.details, dict) else {}


async def verify_crushftp_session(details: dict[str, Any]) -> VerifyStatus:
    cookies = open_session_cookies(details)
    base = (details.get("verify_base_url") or "").strip()
    expected = (details.get("robotic_username") or "").strip()
    if not cookies.get("CrushAuth") or not base:
        return "unknown"
    tls_verify = bool(details.get("upstream_tls_verify", False))
    verify_host = (details.get("verify_host") or "").strip()
    request_headers = (
        {
            "Host": verify_host,
            "Origin": f"https://{verify_host}",
            "Referer": f"https://{verify_host}/",
        }
        if verify_host
        else None
    )
    session = CrushFTPSession(
        cookies=dict(cookies),
        base_url=base,
        tls_verify=tls_verify,
        request_headers=request_headers,
    )
    driver = CrushFTPDriver()
    try:
        identity = await driver.get_username(session)
    except RoboticLoginError:
        return "invalid"
    except Exception:
        logger.exception("crushftp live verify unexpected error")
        return "unknown"
    if expected and identity != expected:
        return "invalid"
    return "active"


async def verify_generic_form_session(details: dict[str, Any]) -> VerifyStatus:
    """
    Best-effort: GET verify_base_url with stored cookies.
    401/403 or redirect toward login → invalid; 2xx → active; else unknown.

    Generic apps have no universal identity probe — documented limitation.
    """
    cookies = open_session_cookies(details)
    base = (details.get("verify_base_url") or "").strip()
    if not cookies or not base:
        return "unknown"
    tls_verify = bool(details.get("upstream_tls_verify", False))
    try:
        async with httpx.AsyncClient(
            timeout=_VERIFY_TIMEOUT,
            follow_redirects=False,
            verify=tls_verify,
            cookies=cookies,
        ) as client:
            response = await client.get(base)
    except httpx.TimeoutException:
        return "unknown"
    except httpx.RequestError:
        return "unknown"

    if response.status_code in (401, 403):
        return "invalid"
    if response.status_code in (301, 302, 303, 307, 308):
        loc = (response.headers.get("location") or "").lower()
        if any(tok in loc for tok in ("login", "signin", "auth", "sso")):
            return "invalid"
        return "unknown"
    if 200 <= response.status_code < 300:
        return "active"
    return "unknown"


async def verify_driven_session(row: ActiveSession) -> VerifyStatus:
    return await verify_driven_details(_details_dict(row))


async def verify_driven_details(details: dict[str, Any]) -> VerifyStatus:
    driver = (details.get("driver") or "").strip().lower()
    if driver == "crushftp":
        return await verify_crushftp_session(details)
    if driver == "generic_form":
        return await verify_generic_form_session(details)
    return "unknown"


def _apply_verify_outcome(
    db: Session,
    row: ActiveSession,
    *,
    status: VerifyStatus,
    now,
    actor: str | None,
    email: str,
    ip_address: str | None,
    revoke_active_session,
    min_strike_gap: timedelta = timedelta(0),
) -> tuple[bool, dict[str, Any]]:
    """Update row from verify status. Returns (revoked, result_payload)."""
    details = _details_dict(row)
    prev_invalid_at = (
        _aware(row.last_verified_at)
        if (row.last_verified_status or "").strip().lower() == "invalid"
        else None
    )
    if status == "active":
        details["consecutive_invalid_count"] = 0
        row.last_verified_status = "active"
        row.last_verified_at = now
        row.details = details
        return False, {
            "id": row.id,
            "last_verified_status": status,
            "last_verified_at": now.isoformat(),
            "consecutive_invalid_count": 0,
            "revoked": False,
        }

    if status == "invalid":
        streak = int(details.get("consecutive_invalid_count") or 0)
        if prev_invalid_at is None or _aware(now) - prev_invalid_at >= min_strike_gap:
            streak += 1
        details["consecutive_invalid_count"] = streak
        row.last_verified_status = "invalid"
        row.last_verified_at = now
        row.details = details
        if streak >= _INVALID_STREAK_TO_REVOKE:
            session_id = row.id
            revoke_active_session(
                db,
                row,
                actor=actor or email,
                reason="downstream_session_expired",
                ip_address=ip_address,
                delete=True,
            )
            return True, {
                "id": session_id,
                "last_verified_status": "invalid",
                "last_verified_at": now.isoformat(),
                "consecutive_invalid_count": streak,
                "revoked": True,
                "reason": "downstream_session_expired",
            }
        return False, {
            "id": row.id,
            "last_verified_status": status,
            "last_verified_at": now.isoformat(),
            "consecutive_invalid_count": streak,
            "revoked": False,
        }

    row.last_verified_status = "unknown"
    row.last_verified_at = now
    return False, {
        "id": row.id,
        "last_verified_status": status,
        "last_verified_at": now.isoformat(),
        "consecutive_invalid_count": int(
            (_details_dict(row).get("consecutive_invalid_count") or 0)
        ),
        "revoked": False,
    }


async def live_verify_user_sessions(
    db: Session,
    *,
    user_email: str,
    actor: str | None = None,
    ip_address: str | None = None,
) -> list[dict[str, Any]]:
    """
    Verify all driven app sessions for one user.

    After two consecutive explicit ``invalid`` results, auto-revoke (delete)
    the bastion session via the shared revoke path. ``unknown`` is neutral
    (no streak change, no revoke).
    """
    from sqlalchemy import or_

    from app.web.sessions_service import identity_match_keys, revoke_active_session

    email = (user_email or "").strip().lower()
    if not email:
        return []
    local = email.split("@", 1)[0] if "@" in email else email
    emails, usernames = identity_match_keys(email=email, username=local)
    clauses = []
    if emails:
        clauses.append(ActiveSession.user_email.in_(emails))
        clauses.append(ActiveSession.username.in_(emails))
    if usernames:
        clauses.append(ActiveSession.user_email.in_(usernames))
        clauses.append(ActiveSession.username.in_(usernames))
    if not clauses:
        return []

    rows = (
        db.query(ActiveSession)
        .filter(
            ActiveSession.kind == "app",
            ActiveSession.status != "isolated",
            or_(*clauses),
        )
        .all()
    )
    results: list[dict[str, Any]] = []
    now = utcnow()
    for row in list(rows):
        if not is_driven_session(row):
            continue
        status = await verify_driven_session(row)
        _revoked, payload = _apply_verify_outcome(
            db,
            row,
            status=status,
            now=now,
            actor=actor,
            email=email,
            ip_address=ip_address,
            revoke_active_session=revoke_active_session,
        )
        results.append(payload)

    db.commit()
    return results


def _identity_clauses(user_email: str):
    from sqlalchemy import or_

    from app.web.sessions_service import identity_match_keys

    email = (user_email or "").strip().lower()
    local = email.split("@", 1)[0] if "@" in email else email
    emails, usernames = identity_match_keys(email=email, username=local)
    keys = sorted(emails | usernames)
    if not keys:
        return None
    return or_(ActiveSession.user_email.in_(keys), ActiveSession.username.in_(keys))


def _load_due_probes(
    user_email: str | None, *, now: datetime
) -> list[tuple[str, dict[str, Any]]]:
    from sqlalchemy import or_

    from app import database

    db = database.SessionLocal()
    try:
        q = db.query(ActiveSession).filter(
            ActiveSession.kind == "app",
            ActiveSession.status != "isolated",
            or_(
                ActiveSession.last_verified_at.is_(None),
                ActiveSession.last_verified_at <= now - PROBE_MIN_INTERVAL,
            ),
        )
        if user_email:
            clause = _identity_clauses(user_email)
            if clause is None:
                return []
            q = q.filter(clause)
        rows = [r for r in q.all() if is_driven_session(r)]
        rows.sort(key=lambda r: _aware(r.last_verified_at) or datetime.min.replace(tzinfo=timezone.utc))
        return [(r.id, _details_dict(r)) for r in rows[:_PROBE_BATCH]]
    finally:
        db.close()


def _apply_due_probes(
    results: list[tuple[str, VerifyStatus]], *, loaded_at: datetime, actor: str
) -> int:
    from app import database
    from app.web.sessions_service import revoke_active_session

    db = database.SessionLocal()
    revoked = 0
    try:
        for session_id, status in results:
            row = db.query(ActiveSession).filter_by(id=session_id).first()
            if row is None or row.status == "isolated":
                continue
            checked = _aware(row.last_verified_at)
            if checked is not None and checked >= loaded_at:
                continue  # another viewer / worker probed it meanwhile
            was_revoked, _payload = _apply_verify_outcome(
                db,
                row,
                status=status,
                now=utcnow(),
                actor=actor,
                email=row.user_email,
                ip_address=None,
                revoke_active_session=revoke_active_session,
                min_strike_gap=STREAM_STRIKE_GAP,
            )
            revoked += int(was_revoked)
            db.commit()
        return revoked
    except Exception:
        logger.exception("background session probe apply failed")
        db.rollback()
        return revoked
    finally:
        db.close()


async def verify_due_driven_sessions(
    *, user_email: str | None = None, actor: str = "system:sessions-live"
) -> int:
    """Probe driven app sessions not checked for PROBE_MIN_INTERVAL.

    ``user_email`` scopes the probe to one identity (non-admin viewer). DB work
    runs in a thread; upstream probes run concurrently (bounded). Returns the
    number of probes performed.
    """
    loaded_at = utcnow()
    due = await asyncio.to_thread(_load_due_probes, user_email, now=loaded_at)
    if not due:
        return 0
    gate = asyncio.Semaphore(_PROBE_CONCURRENCY)

    async def _probe(details: dict[str, Any]) -> VerifyStatus:
        async with gate:
            try:
                return await verify_driven_details(details)
            except Exception:
                logger.exception("background session probe failed")
                return "unknown"

    statuses = await asyncio.gather(*(_probe(details) for _sid, details in due))
    results = [(sid, status) for (sid, _d), status in zip(due, statuses)]
    await asyncio.to_thread(_apply_due_probes, results, loaded_at=loaded_at, actor=actor)
    return len(results)
