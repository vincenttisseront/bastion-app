"""Native bastion OIDC BFF login: headless Keycloak auth + bastion_session JWT."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import get_db
from app.auth.jwt_audience import (
    DEFAULT_OIDC_SESSION_JWT_AUDIENCE,
    jwt_audience_matches,
    resolve_oidc_session_jwt_audience,
)
from app.models import OidcLoginAttempt, OidcSession, RealmConfig, utcnow
from app.auth.oidc_bff_client import (
    InvalidCredentialsError,
    InvalidOtpError,
    LoginStepResult,
    OidcBffConfigError,
    OidcBffError,
    UnsupportedAuthFlowError,
    extract_groups_from_oidc_claims,
    start_headless_login,
    submit_headless_otp,
)
from app.auth.oidc_bff_config_service import resolve_oidc_session_jwt_secret
from app.auth.oidc_native_session import (
    is_oidc_mfa_enabled_for_realm,
    is_oidc_native_session_enabled_for_realm,
)
from app.pathutil import sanitize_log_value
from app.realm_lookup import find_realm
from app.request_client_ip import client_ip_from_request
from app.secret_crypto import decrypt_secret
from app.security.banning.engine import (
    clear_failed_login_counters,
    evaluate_login_attempt,
)
from app.session_cookies import clear_portal_cookie, set_portal_cookie
from app.sso_settings import Settings, get_settings
from app.testing_framework.throttle import (
    clear_failures,
    failure_block_retry_after,
    record_failure,
)
from app.web.csrf import portal_signing_secret, verify_csrf_token
from app.web.openapi_responses import RESP_401, RESP_403, RESP_503
from app.web.templates import render

_AUTH_LOGIN_TEMPLATE = "auth/login.html"

logger = logging.getLogger(__name__)

router = APIRouter(tags=["oidc-bff"])

_GENERIC_AUTH_FAILURE = "Identifiants invalides."
_GENERIC_AUTH_BLOCKED = "Compte temporairement bloqué suite à trop de tentatives."
_TOO_MANY_ATTEMPTS = "Trop de tentatives. Réessayez plus tard."
_NATIVE_DISABLED = "Authentification native non activée pour ce realm."
_NATIVE_NOT_CONFIGURED = "OIDC natif non configuré pour ce realm."
_AUTH_UNAVAILABLE = "Authentification temporairement indisponible."
_CSRF_EXPIRED = "Session expirée — rechargez la page et réessayez."
_MFA_DISABLED = (
    "Configuration OTP demandée par l'IdP, mais le MFA est désactivé "
    "pour ce realm dans Bastion. Activez le MFA (Admin → Realms) "
    "ou retirez l'action CONFIGURE_TOTP côté Keycloak."
)
_UNSUPPORTED_FLOW_LOGIN_ERROR = (
    "Keycloak exige une action avant de finaliser la connexion "
    "(souvent un mot de passe temporaire à changer, une vérification e-mail "
    "ou une configuration MFA). Demandez à un administrateur de lever "
    "l’action requise ou de réinitialiser le mot de passe en mode permanent."
)
_BFF_ERROR_LOGIN_ERROR = (
    "Échec d’authentification OIDC (configuration ou échange avec Keycloak). "
    "Réessayez, ou demandez à un administrateur de vérifier le realm "
    "(Test OIDC, client secret, redirect URI)."
)
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
    groups: tuple[str, ...] = ()
    email: str | None = None
    # Keycloak user-session id (ID token ``sid``): lets self-service keep this login.
    kc_sid: str | None = None


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
    groups: list[str] | tuple[str, ...] | None = None,
    email: str | None = None,
    audience: str | None = None,
    kc_sid: str | None = None,
) -> str:
    """Build a native bastion OIDC session JWT (type=oidc, includes jti + aud)."""
    now = datetime.now(timezone.utc)
    group_list = [g for g in (groups or ()) if (g or "").strip()]
    payload: dict[str, Any] = {
        "sub": sub,
        "username": username,
        "realm": realm,
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(seconds=max_age),
        "type": "oidc",
        "aud": (audience or DEFAULT_OIDC_SESSION_JWT_AUDIENCE).strip(),
        "groups": group_list,
    }
    if email:
        payload["email"] = email
    if kc_sid:
        payload["sid"] = kc_sid
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
    groups: list[str] | tuple[str, ...] | None = None,
    email: str | None = None,
    audience: str | None = None,
    kc_sid: str | None = None,
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
        groups=groups,
        email=email,
        audience=audience,
        kc_sid=kc_sid,
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


def _revoke_values(*, revoked_by: str, reason: str, now: datetime) -> dict[str, Any]:
    return {
        "revoked": True,
        "revoked_at": now,
        "revoked_by": revoked_by,
        "revoked_reason": reason,
    }


def purge_expired_oidc_sessions(db: Session) -> int:
    """Mark expired native sessions as revoked (housekeeping — JWT already invalid)."""
    now = utcnow()
    count = (
        db.query(OidcSession)
        .filter(OidcSession.revoked.is_(False), OidcSession.expires_at <= now)
        .update(
            _revoke_values(revoked_by="system", reason="expired", now=now),
            synchronize_session="fetch",
        )
    )
    return int(count or 0)


def is_oidc_jti_revoked(db: Session, jti: str) -> bool:
    """True if this jti must not authenticate (missing, revoked, or expired)."""
    if not jti:
        return True
    row = db.query(OidcSession).filter_by(jti=jti).first()
    if row is None:
        # Native sessions always register a row at issue time.
        return True
    if row.revoked:
        return True
    return row.expires_at is not None and row.expires_at <= utcnow()


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


def _clean_set(values: set[str] | None, *, lower: bool) -> set[str]:
    out = {str(v).strip() for v in (values or set()) if v and str(v).strip()}
    return {v.lower() for v in out} if lower else out


def revoke_oidc_sessions_for_identity(
    db: Session,
    *,
    realm_slug: str | None,
    emails: set[str] | None = None,
    usernames: set[str] | None = None,
    keycloak_subs: set[str] | None = None,
    revoked_by: str,
    reason: str = "admin_disconnect",
) -> int:
    """Revoke native ``bastion_session`` rows for an identity (admin disconnect).

    Keycloak Admin logout alone does not invalidate local JWT jtis — without this,
    the portal cookie stays valid until expiry.
    """
    names = _clean_set(emails, lower=True) | _clean_set(usernames, lower=True)
    subs = _clean_set(keycloak_subs, lower=False)
    matches = []
    if subs:
        matches.append(func.trim(OidcSession.sub).in_(subs))
    if names:
        matches.append(func.lower(func.trim(OidcSession.username)).in_(names))
    if not matches:
        return 0

    q = db.query(OidcSession).filter(OidcSession.revoked.is_(False), or_(*matches))
    slug = (realm_slug or "").strip()
    if slug:
        q = q.filter(OidcSession.realm == slug)
    count = q.update(
        _revoke_values(revoked_by=revoked_by, reason=reason, now=utcnow()),
        synchronize_session="fetch",
    )
    return int(count or 0)


def set_oidc_session_cookie(
    response: Response,
    token: str,
    settings: Settings,
) -> None:
    """Emit ``bastion_session`` on the portal parent domain (mirrors oauth2-proxy ``cookie_domains``)."""
    set_portal_cookie(
        response,
        settings.oidc_session_cookie_name,
        token,
        max_age=settings.oidc_session_max_age,
        settings=settings,
    )


def clear_oidc_session_cookie(response: Response, settings: Settings) -> None:
    clear_portal_cookie(response, settings.oidc_session_cookie_name, settings)


def revoke_oidc_session_from_request(
    request: Request,
    db: Session,
    settings: Settings,
) -> str:
    """Revoke the ``bastion_session`` jti from the request cookie if present.

    Returns the actor string for audit (username/sub or ``unknown``).
    Does not clear the cookie — call ``clear_oidc_session_cookie`` separately.
    """
    raw = request.cookies.get(settings.oidc_session_cookie_name)
    if not raw:
        return "unknown"

    claims = validate_oidc_session_cookie(raw, db=db, settings=settings)
    if claims is not None:
        actor, jti = claims.username or claims.sub, claims.jti
    else:
        actor, jti = _actor_jti_from_unverified_oidc_cookie(raw, db, settings)
    if jti:
        try:
            revoke_oidc_jti(db, jti, revoked_by=str(actor), reason="logout")
            db.commit()
        except LookupError:
            pass
    return actor


def _unverified_oidc_payload(
    raw: str, db: Session, settings: Settings
) -> dict[str, Any] | None:
    """Signature-checked but expiry-agnostic JWT payload (logout / realm recovery)."""
    secret = resolve_oidc_session_jwt_secret(db, settings)
    if not secret:
        return None
    try:
        payload: dict[str, Any] = jwt.decode(
            raw,
            secret,
            algorithms=["HS256"],
            options={"verify_exp": False, "verify_aud": False},
        )
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "oidc":
        return None
    return payload


def _actor_jti_from_unverified_oidc_cookie(
    raw: str, db: Session, settings: Settings
) -> tuple[str, str | None]:
    """Signature-checked but expiry-agnostic decode, so logout can revoke a stale cookie."""
    payload = _unverified_oidc_payload(raw, db, settings)
    if payload is None:
        return "unknown", None
    actor = str(payload.get("username") or payload.get("sub") or "unknown")
    jti_val = payload.get("jti")
    return actor, jti_val if isinstance(jti_val, str) else None


def realm_slug_from_oidc_cookie(
    raw: str, db: Session, settings: Settings
) -> str | None:
    """Return realm from a (possibly expired) ``bastion_session`` cookie."""
    payload = _unverified_oidc_payload(raw, db, settings)
    if payload is None:
        return None
    realm = payload.get("realm")
    if isinstance(realm, str) and realm.strip():
        return realm.strip()
    return None


def _parse_oidc_groups(raw_groups) -> tuple[str, ...]:
    if isinstance(raw_groups, list):
        return tuple(
            str(g).strip()
            for g in raw_groups
            if isinstance(g, (str, int)) and str(g).strip()
        )
    if isinstance(raw_groups, str) and raw_groups.strip():
        return tuple(g.strip() for g in raw_groups.split(",") if g.strip())
    return ()


def _oidc_claims_from_payload(payload: dict) -> OidcSessionClaims | None:
    jti = payload.get("jti")
    sub = payload.get("sub")
    realm = payload.get("realm")
    if not isinstance(jti, str) or not jti:
        return None
    if not isinstance(sub, str) or not sub:
        return None
    if not isinstance(realm, str) or not realm:
        return None
    username = payload.get("username")
    if username is not None and not isinstance(username, str):
        username = None
    exp = payload.get("exp")
    if not isinstance(exp, int):
        return None
    email_raw = payload.get("email")
    email = (
        str(email_raw).strip()
        if isinstance(email_raw, str) and email_raw.strip()
        else None
    )
    return OidcSessionClaims(
        sub=sub,
        username=username,
        realm=realm,
        jti=jti,
        exp=exp,
        type="oidc",
        groups=_parse_oidc_groups(payload.get("groups")),
        email=email,
        kc_sid=sid if isinstance(sid := payload.get("sid"), str) and sid else None,
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
    key = (secret or "").strip() or resolve_oidc_session_jwt_secret(db, settings)
    if not key:
        return None
    try:
        payload = jwt.decode(
            cookie_value,
            key,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "oidc":
        return None
    if not jwt_audience_matches(
        payload,
        resolve_oidc_session_jwt_audience(settings),
        strict=settings.oidc_session_jwt_audience_strict,
    ):
        return None
    claims = _oidc_claims_from_payload(payload)
    if claims is None or is_oidc_jti_revoked(db, claims.jti):
        return None
    return claims


def _safe_login_rd(rd: str | None, *, portal_domain: str = "") -> str:
    from app.auth.flow import safe_post_login_rd

    return safe_post_login_rd(rd, portal_domain=portal_domain, default="/apps")


@dataclass(slots=True)
class _LoginCtx:
    request: Request
    settings: Settings
    db: Session
    username: str
    realm_slug: str
    attempt_id: str | None
    otp_code: str | None
    client_ip: str
    html_mode: bool
    safe_rd: str
    realm: RealmConfig | None = None

    @property
    def otp_step(self) -> bool:
        return bool(self.attempt_id and self.otp_code)

    @property
    def log_user(self) -> str:
        return sanitize_log_value(self.username)


class _LoginRejected(Exception):
    """A login refusal, rendered as the login page (HTML) or an HTTP error (API)."""

    def __init__(
        self,
        status: int,
        message: str,
        *,
        html_message: str | None = None,
        headers: dict[str, str] | None = None,
        **page: Any,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.html_message = html_message or message
        self.headers = headers
        self.page = page


def _render_login(ctx: _LoginCtx, **state: Any):
    from app.web.constants import APP_VERSION
    from app.web.flash import base_template_context
    from app.web.login_surface import login_surface_flags

    page = {"attempt_id": "", "totp_secret_display": "", "qr_data_url": ""}
    page.update({k: v for k, v in state.items() if v is not None})
    return render(
        _AUTH_LOGIN_TEMPLATE,
        **base_template_context(
            ctx.request,
            ctx.settings,
            APP_VERSION,
            hide_chrome=True,
            login_panel="sso",
            form_username=ctx.username,
            **page,
            **login_surface_flags(
                ctx.request, ctx.db, ctx.settings, rd=ctx.safe_rd, preferred_realm=ctx.realm_slug
            ),
        ),
    )


def _rejection_response(ctx: _LoginCtx, exc: _LoginRejected):
    if ctx.html_mode:
        return _render_login(ctx, login_error=exc.html_message, **exc.page)
    raise HTTPException(status_code=exc.status, detail=exc.message, headers=exc.headers)


def _audit(ctx: _LoginCtx, action: str, details: dict[str, Any], *, actor: str | None = None) -> None:
    log_action(
        ctx.db,
        actor=actor or ctx.username or "unknown",
        action=action,
        details=details,
        ip_address=ctx.client_ip or None,
    )


def _record_failed_attempt(
    ctx: _LoginCtx,
    *,
    reason: str,
    action: str = "oidc_login_failed",
    detail: str | None = None,
) -> None:
    _record_login_failure(ctx.client_ip, ctx.username)
    payload: dict[str, Any] = {"realm": ctx.realm_slug, "reason": reason}
    if detail:
        payload["detail"] = detail[:300]
    _audit(ctx, action, payload)


def _totp_setup_display_from_attempt(
    db: Session, attempt_id: str | None, settings: Settings
) -> tuple[str, str]:
    """Recover QR/secret display from a stored attempt (for error re-render)."""
    if not attempt_id:
        return "", ""
    row = db.query(OidcLoginAttempt).filter_by(attempt_id=attempt_id).first()
    if row is None:
        return "", ""
    try:
        blob = json.loads(decrypt_secret(row.otp_form_encrypted, settings))
    except (ValueError, TypeError):
        return "", ""
    if not isinstance(blob, dict) or blob.get("kind") != "totp_setup":
        return "", ""
    return str(blob.get("secret_display") or ""), str(blob.get("qr_data_url") or "")


def _failure_rejection(ctx: _LoginCtx, *, reason: str, action: str, **page: Any) -> _LoginRejected:
    ban_eval = evaluate_login_attempt(
        ctx.db, ip=ctx.client_ip, username=ctx.username, success=False
    )
    _record_failed_attempt(ctx, reason=reason, action=action)
    if ban_eval.ban is not None:
        return _LoginRejected(403, _GENERIC_AUTH_BLOCKED, **page)
    return _LoginRejected(401, _GENERIC_AUTH_FAILURE, **page)


def _otp_retry_page(ctx: _LoginCtx) -> dict[str, Any]:
    """Keep the OTP / TOTP-setup form on screen while the attempt is still alive."""
    if not ctx.attempt_id:
        return {}
    still = ctx.db.query(OidcLoginAttempt).filter_by(attempt_id=ctx.attempt_id).first()
    if still is None:
        return {}
    secret_disp, qr = _totp_setup_display_from_attempt(ctx.db, ctx.attempt_id, ctx.settings)
    if secret_disp or qr:
        return {
            "totp_setup_required": True,
            "attempt_id": ctx.attempt_id,
            "totp_secret_display": secret_disp,
            "qr_data_url": qr,
        }
    return {"otp_required": True, "attempt_id": ctx.attempt_id}


def _login_context(
    request: Request,
    settings: Settings,
    db: Session,
    *,
    username: str,
    realm: str | None,
    rd: str | None,
    attempt_id: str | None,
    otp_code: str | None,
) -> _LoginCtx:
    ctx = _LoginCtx(
        request=request,
        settings=settings,
        db=db,
        username=(username or "").strip(),
        realm_slug=(realm or "").strip() or settings.sso_portal_default_realm_slug,
        attempt_id=(attempt_id or "").strip() or None,
        otp_code=(otp_code or "").strip() or None,
        client_ip=client_ip_from_request(request),
        # Presence of ``rd`` marks a classic HTML form submit (vs JSON API clients).
        html_mode=rd is not None,
        safe_rd=_safe_login_rd(rd, portal_domain=settings.portal_domain or ""),
    )
    if ctx.otp_step:
        # Recover username/realm from attempt for rate-limit + gate (no enumeration).
        row = db.query(OidcLoginAttempt).filter_by(attempt_id=ctx.attempt_id).first()
        if row is not None:
            ctx.username = (row.username or ctx.username).strip()
            ctx.realm_slug = (row.realm or ctx.realm_slug).strip()
    return ctx


def _resolve_login_realm(ctx: _LoginCtx) -> None:
    realm = find_realm(ctx.db, ctx.realm_slug)
    if realm is not None:
        ctx.realm = realm
        ctx.realm_slug = realm.slug
    if not is_oidc_native_session_enabled_for_realm(ctx.db, ctx.realm_slug, ctx.settings):
        raise _LoginRejected(403, _NATIVE_DISABLED)


def _check_login_allowed(ctx: _LoginCtx) -> None:
    # SecurityBan decision (SQL, cross-worker) — independent from the 429 throttle.
    pre = evaluate_login_attempt(ctx.db, ip=ctx.client_ip, username=ctx.username, success=True)
    if not pre.allowed and pre.ban is not None:
        raise _LoginRejected(
            403,
            _GENERIC_AUTH_BLOCKED,
            otp_required=ctx.otp_step,
            attempt_id=ctx.attempt_id if ctx.otp_step else None,
        )
    wait = _check_login_rate_limit(ctx.client_ip, ctx.username)
    if wait is not None:
        raise _LoginRejected(
            429,
            _TOO_MANY_ATTEMPTS,
            html_message=_GENERIC_AUTH_FAILURE,
            headers={"Retry-After": str(max(1, int(wait)))},
            otp_required=ctx.otp_step,
            attempt_id=ctx.attempt_id,
        )


async def _run_login_step(ctx: _LoginCtx, password: str) -> LoginStepResult:
    try:
        if ctx.otp_step:
            return await submit_headless_otp(
                ctx.attempt_id or "", ctx.otp_code or "", settings=ctx.settings, db=ctx.db
            )
        if not ctx.username or not password:
            raise InvalidCredentialsError("Identifiants incomplets")
        return await start_headless_login(
            ctx.realm_slug, ctx.username, password, settings=ctx.settings, db=ctx.db
        )
    except InvalidOtpError:
        page = _otp_retry_page(ctx)
        raise _failure_rejection(
            ctx, reason="invalid_otp", action="oidc_login_otp_failed", **page
        ) from None
    except InvalidCredentialsError:
        logger.warning(
            "oidc_login invalid_credentials realm=%s user=%s", ctx.realm_slug, ctx.log_user
        )
        raise _failure_rejection(
            ctx, reason="invalid_credentials", action="oidc_login_failed"
        ) from None
    except UnsupportedAuthFlowError as exc:
        detail = str(exc) or "unsupported_flow"
        _record_login_failure(ctx.client_ip, ctx.username)
        logger.warning(
            "oidc_login unsupported flow realm=%s user=%s detail=%s",
            ctx.realm_slug,
            ctx.log_user,
            detail[:200],
        )
        _audit(
            ctx,
            "oidc_login_unsupported_flow",
            {"realm": ctx.realm_slug, "reason": "unsupported_flow", "detail": detail[:300]},
        )
        raise _LoginRejected(
            401, _GENERIC_AUTH_FAILURE, html_message=_UNSUPPORTED_FLOW_LOGIN_ERROR
        ) from None
    except OidcBffConfigError as exc:
        logger.exception(
            "oidc_login misconfigured realm=%s: %s", ctx.realm_slug, type(exc).__name__
        )
        detail = str(exc)
        if "non configuré" not in detail.lower():
            detail = _NATIVE_NOT_CONFIGURED
        raise _LoginRejected(503, detail) from None
    except OidcBffError as exc:
        detail = str(exc) or "bff_error"
        logger.warning(
            "oidc_login BFF error realm=%s user=%s detail=%s",
            ctx.realm_slug,
            ctx.log_user,
            detail[:200],
        )
        _record_failed_attempt(ctx, reason="bff_error", detail=detail)
        raise _LoginRejected(
            401, _GENERIC_AUTH_FAILURE, html_message=_BFF_ERROR_LOGIN_ERROR
        ) from None


async def _resolve_session_groups(
    ctx: _LoginCtx,
    *,
    sub: str,
    claim_groups: tuple[str, ...] | list[str] | None,
) -> tuple[str, ...]:
    """Prefer OIDC token groups; fall back to Keycloak Admin API (BFF client may lack mapper)."""
    claimed = extract_groups_from_oidc_claims({"groups": list(claim_groups or ())})
    if claimed:
        return claimed

    from app.rbac.keycloak_admin import fetch_user_groups

    realm = ctx.realm
    if realm is None or not realm.enabled or not (sub or "").strip():
        return ()
    try:
        kc_groups = await fetch_user_groups(realm, sub, ctx.settings)
    except Exception:
        logger.warning(
            "oidc_login groups Admin API fallback failed realm=%s sub=%s",
            ctx.realm_slug,
            sub,
            exc_info=True,
        )
        return ()

    names = [
        str(raw).strip()
        for entry in kc_groups
        if isinstance(entry, dict)
        and (raw := entry.get("path") or entry.get("name")) is not None
        and str(raw).strip()
    ]
    return extract_groups_from_oidc_claims({"groups": names})


def _challenge_response(ctx: _LoginCtx, step: LoginStepResult):
    """Persist the pending attempt and ask for the OTP (or TOTP enrolment)."""
    aid = step.attempt_id or ""
    totp = step.status == "totp_setup_required"
    if totp and not is_oidc_mfa_enabled_for_realm(ctx.db, ctx.realm_slug, realm=ctx.realm):
        raise _LoginRejected(403, _MFA_DISABLED)
    ctx.db.commit()
    _audit(
        ctx,
        "oidc_login_totp_setup_required" if totp else "oidc_login_otp_required",
        {"realm": ctx.realm_slug, "attempt_id": aid},
    )
    if totp:
        if ctx.html_mode:
            return _render_login(
                ctx,
                totp_setup_required=True,
                attempt_id=aid,
                totp_secret_display=step.totp_secret_display,
                qr_data_url=step.qr_data_url,
            )
        return {
            "status": "totp_setup_required",
            "attempt_id": aid,
            "totp_secret_display": step.totp_secret_display or "",
            "qr_data_url": step.qr_data_url or "",
        }
    if ctx.html_mode:
        return _render_login(ctx, otp_required=True, attempt_id=aid)
    return {"status": "otp_required", "attempt_id": aid}


async def _complete_login(ctx: _LoginCtx, step: LoginStepResult):
    if step.status in ("otp_required", "totp_setup_required"):
        return _challenge_response(ctx, step)

    tokens = step.tokens
    if tokens is None:
        raise _LoginRejected(401, _GENERIC_AUTH_FAILURE)

    secret = resolve_oidc_session_jwt_secret(ctx.db, ctx.settings)
    if not secret:
        raise _LoginRejected(503, _AUTH_UNAVAILABLE)

    display_username = (tokens.preferred_username or ctx.username or "").strip() or None
    session_groups = await _resolve_session_groups(
        ctx, sub=tokens.sub, claim_groups=tokens.groups
    )
    session_email = (tokens.email or "").strip() or None
    if not session_email and display_username and "@" in display_username:
        session_email = display_username

    try:
        from app.rbac.account_lifecycle_service import touch_bastion_login

        touch_bastion_login(
            ctx.db,
            keycloak_user_id=tokens.sub,
            email=session_email or ctx.email,
            username=display_username or ctx.username,
        )
    except Exception:
        logger.debug("bastion last_login touch skipped", exc_info=True)

    token, jti = issue_oidc_session(
        ctx.db,
        sub=tokens.sub,
        username=display_username,
        realm=ctx.realm_slug,
        secret=secret,
        max_age=ctx.settings.oidc_session_max_age,
        groups=session_groups,
        email=session_email,
        audience=resolve_oidc_session_jwt_audience(ctx.settings),
        kc_sid=sid if isinstance(sid := tokens.claims.get("sid"), str) and sid else None,
    )
    ctx.db.commit()
    _clear_login_failures(ctx.client_ip, ctx.username)
    # Also clear SQL sliding-window counters: past failures must not re-ban.
    try:
        clear_failed_login_counters(
            ctx.db,
            ips={ctx.client_ip} if (ctx.client_ip or "").strip() else None,
            usernames={ctx.username} if ctx.username else None,
        )
    except Exception:
        logger.exception("oidc_login sql failed-login counters clear failed")
    _audit(
        ctx,
        "oidc_login_otp_success" if ctx.otp_step else "oidc_login_success",
        {"realm": ctx.realm_slug, "jti": jti, "sub": tokens.sub},
        actor=display_username or tokens.sub,
    )
    if ctx.html_mode:
        from app.robotic.session_cookie_hop import redirect_via_subdomain_sso_mirror

        final_rd = redirect_via_subdomain_sso_mirror(
            ctx.safe_rd, portal_domain=ctx.settings.portal_domain or ""
        )
        response: Response = RedirectResponse(url=final_rd, status_code=302)
    else:
        response = JSONResponse(
            {"status": "ok", "username": display_username, "realm": ctx.realm_slug}
        )
    set_oidc_session_cookie(response, token, ctx.settings)
    return response


@router.post("/auth/login", responses=RESP_401 | RESP_403 | RESP_503)
async def oidc_login(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    realm: str | None = Form(None),
    rd: str | None = Form(None),
    attempt_id: str | None = Form(None),
    otp_code: str | None = Form(None),
    csrf_token: str = Form(""),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    ctx = _login_context(
        request,
        settings,
        db,
        username=username,
        realm=realm,
        rd=rd,
        attempt_id=attempt_id,
        otp_code=otp_code,
    )
    try:
        if ctx.html_mode and not verify_csrf_token(request, portal_signing_secret(settings), csrf_token):
            raise _LoginRejected(403, _CSRF_EXPIRED)
        _resolve_login_realm(ctx)
        _check_login_allowed(ctx)
        step = await _run_login_step(ctx, password)
        return await _complete_login(ctx, step)
    except _LoginRejected as exc:
        return _rejection_response(ctx, exc)


@router.post("/auth/logout")
def oidc_logout(
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    """API logout — revoke jtits and clear all browser auth cookies.

    Also returns ``logout_redirect`` so API clients can optionally follow the
    oauth2-proxy sign_out hop (IdP end-session) like ``GET /logout``.
    """
    from app.auth.breakglass import revoke_breakglass_session_from_request
    from app.session_cookies import (
        clear_browser_auth_cookies,
        oauth2_sign_out_path,
        resolve_logout_realm_slug,
    )

    realm_slug = resolve_logout_realm_slug(request, settings, db)
    actor = revoke_oidc_session_from_request(request, db, settings)
    bg_actor = revoke_breakglass_session_from_request(request, db, settings)
    # API responses cannot chain browser IdP logout; clear oauth2 cookies here
    # and expose the sign_out URL for clients that can navigate.
    clear_browser_auth_cookies(response, settings, include_oauth2=True)
    if (not actor or actor == "unknown") and bg_actor and bg_actor != "unknown":
        actor = bg_actor
    log_action(
        db,
        actor=actor,
        action="oidc_logout",
        ip_address=client_ip_from_request(request) or None,
    )
    return {
        "status": "ok",
        "logout_redirect": oauth2_sign_out_path(realm_slug),
    }
