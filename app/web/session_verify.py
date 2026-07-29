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
_INVALID_STREAK_TO_REVOKE = 2


def is_driven_session(row: ActiveSession) -> bool:
    details = row.details if isinstance(row.details, dict) else {}
    driver = (details.get("driver") or "").strip().lower()
    return row.kind == "app" and driver in _DRIVEN_DRIVERS


def _details_dict(row: ActiveSession) -> dict[str, Any]:
    return dict(row.details) if isinstance(row.details, dict) else {}


async def verify_crushftp_session(details: dict[str, Any]) -> VerifyStatus:
    cookies = details.get("session_cookies") or {}
    base = (details.get("verify_base_url") or "").strip()
    expected = (details.get("robotic_username") or "").strip()
    if not cookies.get("CrushAuth") or not base:
        return "unknown"
    tls_verify = bool(details.get("upstream_tls_verify", False))
    session = CrushFTPSession(
        cookies=dict(cookies),
        base_url=base,
        tls_verify=tls_verify,
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
    cookies = details.get("session_cookies") or {}
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
    details = _details_dict(row)
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
    actor: str | None = None,
    ip_address: str | None = None,
) -> list[dict[str, Any]]:
    """
    Verify all driven app sessions for one user.

    After two consecutive explicit ``invalid`` results, auto-revoke (delete)
    the bastion session via the shared revoke path. ``unknown`` is neutral
    (no streak change, no revoke).
    """
    from app.web.sessions_service import revoke_active_session

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
    for row in list(rows):
        if not is_driven_session(row):
            continue
        status = await verify_driven_session(row)
        details = _details_dict(row)
        revoked = False

        if status == "active":
            details["consecutive_invalid_count"] = 0
            row.last_verified_status = "active"
            row.last_verified_at = now
            row.details = details
        elif status == "invalid":
            streak = int(details.get("consecutive_invalid_count") or 0) + 1
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
                revoked = True
                results.append(
                    {
                        "id": session_id,
                        "last_verified_status": "invalid",
                        "last_verified_at": now.isoformat(),
                        "consecutive_invalid_count": streak,
                        "revoked": True,
                        "reason": "downstream_session_expired",
                    }
                )
                continue
        else:
            # unknown: do not change streak, do not revoke
            row.last_verified_status = "unknown"
            row.last_verified_at = now

        if not revoked:
            results.append(
                {
                    "id": row.id,
                    "last_verified_status": status,
                    "last_verified_at": now.isoformat(),
                    "consecutive_invalid_count": int(
                        (_details_dict(row).get("consecutive_invalid_count") or 0)
                    ),
                    "revoked": False,
                }
            )

    db.commit()
    return results
