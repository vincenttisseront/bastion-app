"""Live verification of driven (CrushFTP / generic_form) app sessions."""

from __future__ import annotations

import logging
from typing import Any, Literal

import httpx
from sqlalchemy.orm import Session

from app.bastion.drivers.base import RoboticLoginError
from app.bastion.drivers.crushftp import CrushFTPDriver, CrushFTPSession
from app.models import ActiveSession, utcnow

logger = logging.getLogger(__name__)

VerifyStatus = Literal["active", "invalid", "unknown"]

_DRIVEN_DRIVERS = frozenset({"crushftp", "generic_form"})
_VERIFY_TIMEOUT = 5.0


def is_driven_session(row: ActiveSession) -> bool:
    details = row.details if isinstance(row.details, dict) else {}
    driver = (details.get("driver") or "").strip().lower()
    return row.kind == "app" and driver in _DRIVEN_DRIVERS


async def verify_crushftp_session(details: dict[str, Any]) -> VerifyStatus:
    cookies = details.get("session_cookies") or {}
    base = (details.get("verify_base_url") or "").strip()
    expected = (details.get("robotic_username") or "").strip()
    if not cookies.get("CrushAuth") or not base:
        return "unknown"
    session = CrushFTPSession(cookies=dict(cookies), base_url=base)
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
    cookies = details.get("session_cookies") or {}
    base = (details.get("verify_base_url") or "").strip()
    if not cookies or not base:
        return "unknown"
    try:
        async with httpx.AsyncClient(
            timeout=_VERIFY_TIMEOUT,
            follow_redirects=False,
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
    details = row.details if isinstance(row.details, dict) else {}
    driver = (details.get("driver") or "").strip().lower()
    if driver == "crushftp":
        return await verify_crushftp_session(details)
    if driver == "generic_form":
        return await verify_generic_form_session(details)
    return "unknown"


async def live_verify_user_sessions(
    db: Session,
    *,
    user_email: str,
) -> list[dict[str, Any]]:
    """
    Verify all driven app sessions for one user. Updates DB rows in place.
    Returns [{id, last_verified_status, last_verified_at}, ...].
    """
    email = (user_email or "").strip().lower()
    if not email:
        return []
    rows = (
        db.query(ActiveSession)
        .filter(
            ActiveSession.user_email == email,
            ActiveSession.kind == "app",
            ActiveSession.status != "isolated",
        )
        .all()
    )
    results: list[dict[str, Any]] = []
    now = utcnow()
    for row in rows:
        if not is_driven_session(row):
            continue
        status = await verify_driven_session(row)
        row.last_verified_status = status
        row.last_verified_at = now
        results.append(
            {
                "id": row.id,
                "last_verified_status": status,
                "last_verified_at": now.isoformat(),
            }
        )
    if results:
        db.commit()
    return results
