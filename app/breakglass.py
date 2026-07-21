"""Break-glass login, JWT cookie, and admin routes."""

from datetime import datetime, timedelta, timezone

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
COOKIE_MAX_AGE = 8 * 3600

router = APIRouter(prefix="/api/admin/breakglass", tags=["breakglass"])


class BreakglassLoginBody(BaseModel):
    username: str
    password: str


def create_breakglass_token(username: str, secret: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc) + timedelta(seconds=COOKIE_MAX_AGE),
        "type": "bg",
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def validate_breakglass_cookie(cookie_value: str, secret: str) -> bool:
    """Validate the break-glass JWT. Returns True if valid and not expired."""
    if not secret:
        return False
    try:
        jwt.decode(cookie_value, secret, algorithms=["HS256"])
        return True
    except jwt.PyJWTError:
        return False


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
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="lax",
        domain=settings.portal_domain,
    )
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
        try:
            payload = jwt.decode(
                bg_cookie, settings.vault_portal_internal_token, algorithms=["HS256"]
            )
            username = payload.get("sub", "unknown")
        except jwt.PyJWTError:
            pass

    response.delete_cookie(key=COOKIE_NAME, domain=settings.portal_domain)
    log_action(
        db,
        actor=username,
        action="breakglass.logout",
        ip_address=_client_ip(request),
    )
    return {"status": "ok"}
