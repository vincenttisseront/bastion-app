"""Break-glass login, JWT cookie, and admin routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.audit import log_action
from app.breakglass_store import verify_breakglass_password
from app.database import get_db
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings

COOKIE_NAME = "bg_session"
# Absolute TTL — PROPOSED / documented in architecture (8h). Validated on every decode.
COOKIE_MAX_AGE = 8 * 3600
# Idle timeout — PROPOSED for admin break-glass (stricter than SSO). Sliding via ``last`` claim.
IDLE_TIMEOUT_SECONDS = 30 * 60
# Re-issue cookie at most this often when sliding idle (avoid Set-Cookie spam).
_IDLE_TOUCH_MIN_SECONDS = 60

router = APIRouter(prefix="/api/admin/breakglass", tags=["breakglass"])


class BreakglassLoginBody(BaseModel):
    username: str
    password: str


def create_breakglass_token(username: str, secret: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(seconds=COOKIE_MAX_AGE),
        "last": int(now.timestamp()),
        "type": "bg",
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_breakglass_token(cookie_value: str, secret: str) -> dict[str, Any] | None:
    """Decode and enforce absolute ``exp`` + idle timeout on ``last``."""
    if not secret or not cookie_value:
        return None
    try:
        payload = jwt.decode(cookie_value, secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "bg":
        return None
    if payload.get("exp") is None:
        # Absolute expiry is mandatory (reject legacy tokens without exp).
        return None
    last = payload.get("last")
    if last is None:
        # Legacy tokens without ``last``: treat iat as last activity.
        iat = payload.get("iat")
        if iat is None:
            return None
        last = int(iat) if not isinstance(iat, datetime) else int(iat.timestamp())
    else:
        last = int(last)
    now_ts = int(datetime.now(timezone.utc).timestamp())
    if now_ts - last > IDLE_TIMEOUT_SECONDS:
        return None
    return payload


def validate_breakglass_cookie(cookie_value: str, secret: str) -> bool:
    """Validate the break-glass JWT (absolute exp + idle). Returns True if usable."""
    return decode_breakglass_token(cookie_value, secret) is not None


def maybe_refresh_breakglass_cookie(
    cookie_value: str,
    secret: str,
) -> str | None:
    """
    If the token is valid and idle window should slide, return a new JWT.
    Absolute ``exp`` is preserved from the original token (hard wall from login).
    """
    payload = decode_breakglass_token(cookie_value, secret)
    if payload is None:
        return None
    now = datetime.now(timezone.utc)
    now_ts = int(now.timestamp())
    last = int(payload.get("last") or now_ts)
    if now_ts - last < _IDLE_TOUCH_MIN_SECONDS:
        return None
    exp = payload.get("exp")
    if isinstance(exp, datetime):
        exp_dt = exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
    elif isinstance(exp, (int, float)):
        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
    else:
        return None
    # Do not extend past absolute expiry
    if now >= exp_dt:
        return None
    refreshed = {
        "sub": payload.get("sub"),
        "iat": payload.get("iat"),
        "exp": exp_dt,
        "last": now_ts,
        "type": "bg",
    }
    return jwt.encode(refreshed, secret, algorithm="HS256")


def set_breakglass_cookie(
    response: Response,
    token: str,
    settings: Settings,
    *,
    max_age: int | None = None,
) -> None:
    # Host-only cookie (no Domain=) so it stays on the portal host and works in tests.
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=max_age if max_age is not None else COOKIE_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="lax",
    )


def _client_ip(request: Request) -> str:
    return client_ip_from_request(request)


@router.post("/login")
async def breakglass_login(
    body: BreakglassLoginBody,
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    if not settings.vault_portal_internal_token:
        raise HTTPException(status_code=503, detail="Internal token not configured")

    if not verify_breakglass_password(db, body.username, body.password):
        log_action(
            db,
            actor=body.username,
            action="breakglass.login_failed",
            ip_address=_client_ip(request),
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_breakglass_token(body.username, settings.vault_portal_internal_token)
    set_breakglass_cookie(response, token, settings)
    log_action(
        db,
        actor=body.username,
        action="breakglass.login",
        ip_address=_client_ip(request),
    )
    return {"status": "ok", "username": body.username}


@router.post("/logout")
async def breakglass_logout(
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    username = "unknown"
    bg_cookie = request.cookies.get(COOKIE_NAME)
    if bg_cookie and settings.vault_portal_internal_token:
        payload = decode_breakglass_token(bg_cookie, settings.vault_portal_internal_token)
        if payload:
            username = payload.get("sub", "unknown")
        else:
            try:
                # Logout even if idle-expired: read sub without idle check
                raw = jwt.decode(
                    bg_cookie,
                    settings.vault_portal_internal_token,
                    algorithms=["HS256"],
                    options={"verify_exp": False},
                )
                username = raw.get("sub", "unknown")
            except jwt.PyJWTError:
                pass

    response.delete_cookie(key=COOKIE_NAME)
    log_action(
        db,
        actor=username,
        action="breakglass.logout",
        ip_address=_client_ip(request),
    )
    return {"status": "ok"}
