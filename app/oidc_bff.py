"""Native bastion OIDC BFF login: headless Keycloak auth + bastion_session JWT."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import get_db
from app.models import OidcSession, utcnow
from app.oidc_bff_client import (
    InvalidCredentialsError,
    OidcBffConfigError,
    OidcBffError,
    UnsupportedAuthFlowError,
    perform_headless_login,
)
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings
from app.testing_framework.throttle import (
    clear_failures,
    failure_block_retry_after,
    record_failure,
)
from app.web.templates import render

logger = logging.getLogger(__name__)

router = APIRouter(tags=["oidc-bff"])

_GENERIC_AUTH_FAILURE = "Identifiants invalides."
# Sliding-window brute-force protection (process-local; no Redis).
OIDC_LOGIN_MAX_FAILURES = 5
OIDC_LOGIN_FAILURE_WINDOW_SECONDS = 60.0
_RATE_RESOURCE = "oidc_login"


@dataclass(frozen=True, slots=True)
class OidcSessionClaims:
    sub: str
    username: str | None
    realm: str
    jti: str
    exp: int
    type: str = "oidc"


def _client_ip(request: Request) -> str:
    return client_ip_from_request(request)


def _rate_key(ip: str, username: str) -> str:
    return f"{(ip or 'unknown').strip()}:{(username or '').strip().lower()}"


def _check_login_rate_limit(ip: str, username: str) -> float | None:
    return failure_block_retry_after(
        _RATE_RESOURCE,
        _rate_key(ip, username),
        max_failures=OIDC_LOGIN_MAX_FAILURES,
        window_seconds=OIDC_LOGIN_FAILURE_WINDOW_SECONDS,
    )


def _record_login_failure(ip: str, username: str) -> None:
    record_failure(
        _RATE_RESOURCE,
        _rate_key(ip, username),
        window_seconds=OIDC_LOGIN_FAILURE_WINDOW_SECONDS,
    )


def _clear_login_failures(ip: str, username: str) -> None:
    clear_failures(_RATE_RESOURCE, _rate_key(ip, username))


def create_oidc_session_token(
    *,
    sub: str,
    username: str | None,
    realm: str,
    jti: str,
    secret: str,
    max_age: int,
) -> str:
    """Build a native bastion OIDC session JWT (type=oidc, includes jti)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "username": username,
        "realm": realm,
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(seconds=max_age),
        "type": "oidc",
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def register_oidc_session(
    db: Session,
    *,
    jti: str,
    sub: str,
    username: str | None,
    realm: str,
    expires_at: datetime,
    issued_at: datetime | None = None,
) -> OidcSession:
    row = OidcSession(
        jti=jti,
        sub=sub,
        username=username,
        realm=realm,
        issued_at=issued_at or utcnow(),
        expires_at=expires_at,
        revoked=False,
    )
    db.add(row)
    db.flush()
    return row


def issue_oidc_session(
    db: Session,
    *,
    sub: str,
    username: str | None,
    realm: str,
    secret: str,
    max_age: int,
) -> tuple[str, str]:
    """Create JWT + OidcSession row. Returns ``(token, jti)``."""
    jti = str(uuid4())
    token = create_oidc_session_token(
        sub=sub,
        username=username,
        realm=realm,
        jti=jti,
        secret=secret,
        max_age=max_age,
    )
    now = datetime.now(timezone.utc)
    register_oidc_session(
        db,
        jti=jti,
        sub=sub,
        username=username,
        realm=realm,
        issued_at=now,
        expires_at=now + timedelta(seconds=max_age),
    )
    return token, jti


def is_oidc_jti_revoked(db: Session, jti: str) -> bool:
    """True if this jti must not authenticate (missing or revoked)."""
    if not jti:
        return True
    row = db.query(OidcSession).filter_by(jti=jti).first()
    if row is None:
        # Native sessions always register a row at issue time.
        return True
    return bool(row.revoked)


def revoke_oidc_jti(
    db: Session,
    jti: str,
    *,
    revoked_by: str,
    reason: str | None = None,
) -> OidcSession:
    row = db.query(OidcSession).filter_by(jti=jti).first()
    if row is None:
        raise LookupError("oidc session not found")
    if not row.revoked:
        row.revoked = True
        row.revoked_at = utcnow()
        row.revoked_by = revoked_by
        row.revoked_reason = (reason or "").strip() or None
    db.flush()
    return row


def set_oidc_session_cookie(
    response: Response,
    token: str,
    settings: Settings,
) -> None:
    response.set_cookie(
        key=settings.oidc_session_cookie_name,
        value=token,
        max_age=settings.oidc_session_max_age,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )


def clear_oidc_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=settings.oidc_session_cookie_name,
        path="/",
    )


def validate_oidc_session_cookie(
    cookie_value: str,
    *,
    db: Session,
    settings: Settings | None = None,
    secret: str | None = None,
) -> OidcSessionClaims | None:
    """
    Decode the native OIDC session JWT and enforce the jti denylist.

    Returns None for any invalid / expired / revoked cookie (no error detail).
    """
    if not cookie_value:
        return None
    settings = settings or get_settings()
    key = (secret or "").strip()
    if not key:
        from app.oidc_bff_config_service import resolve_oidc_session_jwt_secret

        key = resolve_oidc_session_jwt_secret(db, settings)
    if not key:
        return None
    try:
        payload = jwt.decode(cookie_value, key, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "oidc":
        return None
    jti = payload.get("jti")
    sub = payload.get("sub")
    realm = payload.get("realm")
    if not isinstance(jti, str) or not jti:
        return None
    if not isinstance(sub, str) or not sub:
        return None
    if not isinstance(realm, str) or not realm:
        return None
    if is_oidc_jti_revoked(db, jti):
        return None
    username = payload.get("username")
    if username is not None and not isinstance(username, str):
        username = None
    exp = payload.get("exp")
    if not isinstance(exp, int):
        return None
    return OidcSessionClaims(
        sub=sub,
        username=username,
        realm=realm,
        jti=jti,
        exp=exp,
        type="oidc",
    )


def _auth_failure_response(
    db: Session,
    *,
    request: Request,
    username: str,
    realm: str,
    reason: str,
) -> None:
    """Record failure + audit, then raise generic 401 (no credential enumeration)."""
    ip = _client_ip(request)
    _record_login_failure(ip, username)
    log_action(
        db,
        actor=username or "unknown",
        action="oidc_login_failed",
        details={"realm": realm, "reason": reason},
        ip_address=ip or None,
    )
    raise HTTPException(status_code=401, detail=_GENERIC_AUTH_FAILURE)


def _safe_login_rd(rd: str | None) -> str:
    value = (rd or "").strip() or "/apps"
    if not value.startswith("/") or value.startswith("//"):
        return "/apps"
    if value in ("/dashboard", "/admin/dashboard"):
        return "/apps"
    return value


def _html_login_error(
    request: Request,
    settings: Settings,
    db: Session,
    *,
    rd: str,
    username: str,
    login_error: str,
):
    """Re-render the public login page with a generic error (HTML form posts)."""
    from app.web.constants import APP_VERSION
    from app.web.flash import base_template_context
    from app.web.pages import _login_surface_flags

    return render(
        "auth/login.html",
        **base_template_context(
            request,
            settings,
            APP_VERSION,
            hide_chrome=True,
            login_error=login_error,
            form_username=username,
            **_login_surface_flags(request, db, settings, rd=rd),
        ),
    )


def _record_failed_attempt(
    db: Session,
    *,
    request: Request,
    username: str,
    realm: str,
    reason: str,
    action: str = "oidc_login_failed",
) -> None:
    ip = _client_ip(request)
    _record_login_failure(ip, username)
    log_action(
        db,
        actor=username or "unknown",
        action=action,
        details={"realm": realm, "reason": reason},
        ip_address=ip or None,
    )


def _record_unsupported_flow(
    db: Session,
    *,
    request: Request,
    username: str,
    realm: str,
    detail: str,
) -> None:
    """Admin-visible audit when Keycloak requires MFA / required-action (not silent 401)."""
    ip = _client_ip(request)
    _record_login_failure(ip, username)
    logger.warning(
        "oidc_login unsupported flow realm=%s user=%s detail=%s",
        realm,
        username,
        detail[:200],
    )
    log_action(
        db,
        actor=username or "unknown",
        action="oidc_login_unsupported_flow",
        details={
            "realm": realm,
            "reason": "unsupported_flow",
            "detail": (detail or "")[:300],
        },
        ip_address=ip or None,
    )


@router.post("/auth/login")
async def oidc_login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    realm: str | None = Form(None),
    rd: str | None = Form(None),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    from app.oidc_native_session import is_oidc_native_session_enabled_for_realm

    username = (username or "").strip()
    realm_slug = (realm or "").strip() or settings.sso_portal_default_realm_slug
    client_ip = _client_ip(request)
    # Presence of ``rd`` marks a classic HTML form submit (vs JSON API clients).
    html_mode = rd is not None
    safe_rd = _safe_login_rd(rd)

    if not is_oidc_native_session_enabled_for_realm(db, realm_slug, settings):
        if html_mode:
            return _html_login_error(
                request,
                settings,
                db,
                rd=safe_rd,
                username=username,
                login_error="Authentification native non activée pour ce realm.",
            )
        raise HTTPException(
            status_code=403,
            detail="Authentification native non activée pour ce realm.",
        )

    wait = _check_login_rate_limit(client_ip, username)
    if wait is not None:
        if html_mode:
            return _html_login_error(
                request,
                settings,
                db,
                rd=safe_rd,
                username=username,
                login_error=_GENERIC_AUTH_FAILURE,
            )
        raise HTTPException(
            status_code=429,
            detail="Trop de tentatives. Réessayez plus tard.",
            headers={"Retry-After": str(max(1, int(wait)))},
        )

    try:
        tokens = await perform_headless_login(
            realm_slug, username, password, settings=settings, db=db
        )
    except InvalidCredentialsError:
        if html_mode:
            _record_failed_attempt(
                db,
                request=request,
                username=username,
                realm=realm_slug,
                reason="invalid_credentials",
            )
            return _html_login_error(
                request,
                settings,
                db,
                rd=safe_rd,
                username=username,
                login_error=_GENERIC_AUTH_FAILURE,
            )
        _auth_failure_response(
            db, request=request, username=username, realm=realm_slug, reason="invalid_credentials"
        )
    except UnsupportedAuthFlowError as exc:
        detail = str(exc) or "unsupported_flow"
        _record_unsupported_flow(
            db,
            request=request,
            username=username,
            realm=realm_slug,
            detail=detail,
        )
        if html_mode:
            return _html_login_error(
                request,
                settings,
                db,
                rd=safe_rd,
                username=username,
                login_error=_GENERIC_AUTH_FAILURE,
            )
        raise HTTPException(status_code=401, detail=_GENERIC_AUTH_FAILURE) from None
    except OidcBffConfigError as exc:
        logger.error("oidc_login misconfigured realm=%s: %s", realm_slug, type(exc).__name__)
        detail = str(exc) or "OIDC natif non configuré pour ce realm."
        if "non configuré" not in detail.lower():
            detail = "OIDC natif non configuré pour ce realm."
        if html_mode:
            return _html_login_error(
                request,
                settings,
                db,
                rd=safe_rd,
                username=username,
                login_error=detail,
            )
        raise HTTPException(status_code=503, detail=detail) from None
    except OidcBffError:
        logger.warning("oidc_login BFF error realm=%s user=%s", realm_slug, username)
        if html_mode:
            _record_failed_attempt(
                db,
                request=request,
                username=username,
                realm=realm_slug,
                reason="bff_error",
            )
            return _html_login_error(
                request,
                settings,
                db,
                rd=safe_rd,
                username=username,
                login_error=_GENERIC_AUTH_FAILURE,
            )
        _auth_failure_response(
            db, request=request, username=username, realm=realm_slug, reason="bff_error"
        )

    display_username = (tokens.preferred_username or username or "").strip() or None
    from app.oidc_bff_config_service import resolve_oidc_session_jwt_secret

    secret = resolve_oidc_session_jwt_secret(db, settings)
    if not secret:
        if html_mode:
            return _html_login_error(
                request,
                settings,
                db,
                rd=safe_rd,
                username=username,
                login_error="Authentification temporairement indisponible.",
            )
        raise HTTPException(
            status_code=503,
            detail="Authentification temporairement indisponible.",
        )

    token, jti = issue_oidc_session(
        db,
        sub=tokens.sub,
        username=display_username,
        realm=realm_slug,
        secret=secret,
        max_age=settings.oidc_session_max_age,
    )
    db.commit()
    _clear_login_failures(client_ip, username)
    log_action(
        db,
        actor=display_username or tokens.sub,
        action="oidc_login_success",
        details={"realm": realm_slug, "jti": jti, "sub": tokens.sub},
        ip_address=client_ip or None,
    )
    if html_mode:
        redirect = RedirectResponse(url=safe_rd, status_code=302)
        set_oidc_session_cookie(redirect, token, settings)
        return redirect

    set_oidc_session_cookie(response, token, settings)
    return {
        "status": "ok",
        "username": display_username,
        "realm": realm_slug,
    }


@router.post("/auth/logout")
async def oidc_logout(
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    actor = "unknown"
    cookie_name = settings.oidc_session_cookie_name
    raw = request.cookies.get(cookie_name)
    if raw:
        # Prefer full validation; fall back to decode without exp for logout revoke.
        claims = validate_oidc_session_cookie(raw, db=db, settings=settings)
        jti: str | None = None
        if claims is not None:
            actor = claims.username or claims.sub
            jti = claims.jti
        else:
            from app.oidc_bff_config_service import resolve_oidc_session_jwt_secret

            secret = resolve_oidc_session_jwt_secret(db, settings)
            if secret:
                try:
                    payload: dict[str, Any] = jwt.decode(
                        raw,
                        secret,
                        algorithms=["HS256"],
                        options={"verify_exp": False},
                    )
                    if payload.get("type") == "oidc":
                        actor = str(payload.get("username") or payload.get("sub") or "unknown")
                        jti_val = payload.get("jti")
                        if isinstance(jti_val, str):
                            jti = jti_val
                except jwt.PyJWTError:
                    pass
        if jti:
            try:
                revoke_oidc_jti(db, jti, revoked_by=str(actor), reason="logout")
                db.commit()
            except LookupError:
                pass

    clear_oidc_session_cookie(response, settings)
    log_action(
        db,
        actor=actor,
        action="oidc_logout",
        ip_address=_client_ip(request) or None,
    )
    return {"status": "ok"}
