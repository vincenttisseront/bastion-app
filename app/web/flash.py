"""Flash messages via signed cookie."""

import hashlib
import hmac
import json
from typing import Any

from fastapi import Request, Response

from app.access_modes import ACCESS_MODE_LABELS, ACCESS_MODES
from app.bastion.bastion_fields import (
    AUTH_MODE_LABELS,
    AUTH_MODES,
    CREDENTIAL_MODE_LABELS,
    CREDENTIAL_MODES,
    IDENTITY_FORMAT_LABELS,
    IDENTITY_FORMATS,
)
from app.robotic.robotic_session_cookies import (
    INJECTED_COOKIE_SCOPE_LABELS,
    INJECTED_COOKIE_SCOPES,
)

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
            if data:
                # Consume once: render()/middleware must clear the cookie on the response.
                request.state.flash_consume = True
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
        path="/",
    )


def clear_flash(response: Response) -> None:
    """Delete the flash cookie so the message is not shown on the next page."""
    response.delete_cookie(key=FLASH_COOKIE, path="/", samesite="lax")


def consume_flash_on_response(request: Request, response: Response) -> None:
    """If flash was read for this request, expire the cookie on the outgoing response."""
    if getattr(request.state, "flash_consume", False):
        clear_flash(response)


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

    # Prefer the request-scoped session (same DB as Depends(get_db) / tests).
    db = getattr(request.state, "db", None)
    ctx = get_user_context(request, settings, db=db)
    if ctx:
        user = ctx
        is_admin = ctx.is_admin
        realm_slug = ctx.realm_slug

    # Explicit overrides from callers (e.g. portal pages) win.
    if "is_admin" in extra:
        is_admin = bool(extra["is_admin"])

    messages = get_flash_messages(request, secret)

    branding = extra.pop("branding", None)
    if branding is None:
        from app.branding import get_branding_settings

        if db is not None:
            branding = get_branding_settings(db)
        else:
            # Exception handlers / early paths may lack Depends(get_db).
            try:
                from app.database import SessionLocal

                tmp = SessionLocal()
                try:
                    branding = get_branding_settings(tmp)
                finally:
                    tmp.close()
            except Exception:
                branding = get_branding_settings(None)

    ctx_out = {
        "request": request,
        "current_user": user,
        "is_admin": is_admin,
        "is_portal_admin": is_admin,
        "realm_slug": realm_slug,
        "app_version": app_version,
        "messages": messages,
        "csrf_token": make_csrf_token(request, secret),
        "hide_chrome": extra.pop("hide_chrome", False),
        "now": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "access_modes": ACCESS_MODES,
        "access_mode_labels": ACCESS_MODE_LABELS,
        "auth_modes": AUTH_MODES,
        "auth_mode_labels": AUTH_MODE_LABELS,
        "credential_modes": CREDENTIAL_MODES,
        "credential_mode_labels": CREDENTIAL_MODE_LABELS,
        "identity_formats": IDENTITY_FORMATS,
        "identity_format_labels": IDENTITY_FORMAT_LABELS,
        "injected_cookie_scopes": INJECTED_COOKIE_SCOPES,
        "injected_cookie_scope_labels": INJECTED_COOKIE_SCOPE_LABELS,
        "portal_domain": getattr(settings, "portal_domain", "") or "",
        "branding": branding,
        **extra,
    }
    # Keep resolved admin flag even if a caller passed a stale is_admin in extras.
    ctx_out["is_admin"] = is_admin
    ctx_out["is_portal_admin"] = bool(extra.get("is_portal_admin", is_admin))

    # Sidebar badges: pending first-SSO users + public access requests.
    if "pending_users_nav_count" not in ctx_out:
        pending_count = 0
        if is_admin and db is not None and not ctx_out.get("hide_chrome"):
            try:
                from app.models import PendingUser

                pending_count = (
                    db.query(PendingUser)
                    .filter(PendingUser.status == "pending")
                    .count()
                )
            except Exception:
                pending_count = 0
        ctx_out["pending_users_nav_count"] = pending_count

    if "access_requests_nav_count" not in ctx_out:
        ar_count = 0
        if is_admin and db is not None and not ctx_out.get("hide_chrome"):
            try:
                from app.rbac.access_request_service import count_pending_access_requests

                ar_count = count_pending_access_requests(db)
            except Exception:
                ar_count = 0
        ctx_out["access_requests_nav_count"] = ar_count

    return ctx_out
