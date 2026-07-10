"""Flash messages via signed cookie."""

import hashlib
import hmac
import json
from typing import Any

from fastapi import Request, Response

FLASH_COOKIE = "portal_flash"
FLASH_MAX_AGE = 30


def _sign(payload: str, secret: str) -> str:
    if not secret:
        return payload
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _unsign(signed: str, secret: str) -> str | None:
    if not secret or "." not in signed:
        return signed if signed else None
    payload, sig = signed.rsplit(".", 1)
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    return payload


def get_flash_messages(request: Request, secret: str) -> list[dict[str, str]]:
    raw = request.cookies.get(FLASH_COOKIE)
    if not raw:
        return []
    payload = _unsign(raw, secret)
    if not payload:
        return []
    try:
        data = json.loads(payload)
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass
    return []


def set_flash(response: Response, messages: list[dict[str, str]], secret: str) -> None:
    payload = json.dumps(messages)
    signed = _sign(payload, secret)
    response.set_cookie(
        key=FLASH_COOKIE,
        value=signed,
        max_age=FLASH_MAX_AGE,
        httponly=True,
        samesite="lax",
    )


def flash_redirect(response: Response, message: str, category: str, secret: str) -> None:
    set_flash(response, [{"message": message, "category": category}], secret)


def make_csrf_token(request: Request, secret: str) -> str:
    session_key = request.headers.get("X-Email") or request.cookies.get("bg_session", "")[:16]
    raw = f"csrf:{session_key}"
    return hmac.new(secret.encode() or b"dev", raw.encode(), hashlib.sha256).hexdigest()[:32]


def base_template_context(request: Request, settings: Any, app_version: str, **extra: Any) -> dict[str, Any]:
    from datetime import datetime, timezone

    secret = settings.vault_portal_internal_token or "dev-insecure"
    user = None
    is_admin = False
    realm_slug = settings.sso_portal_default_realm_slug

    from app.web.user_context import get_user_context

    ctx = get_user_context(request, settings)
    if ctx:
        user = ctx
        is_admin = ctx.is_admin
        realm_slug = ctx.realm_slug

    messages = get_flash_messages(request, secret)
    return {
        "request": request,
        "current_user": user,
        "is_admin": is_admin,
        "realm_slug": realm_slug,
        "app_version": app_version,
        "messages": messages,
        "csrf_token": make_csrf_token(request, secret),
        "hide_chrome": extra.pop("hide_chrome", False),
        "now": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        **extra,
    }
