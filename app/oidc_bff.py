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
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import get_db
from app.jwt_audience import (
    DEFAULT_OIDC_SESSION_JWT_AUDIENCE,
    jwt_audience_matches,
    resolve_oidc_session_jwt_audience,
)
from app.models import OidcSession, utcnow
from app.oidc_bff_client import (
    InvalidCredentialsError,
    InvalidOtpError,
    OidcBffConfigError,
    OidcBffError,
    UnsupportedAuthFlowError,
    start_headless_login,
    submit_headless_otp,
)
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings
from app.testing_framework.throttle import (
    clear_failures,
    failure_block_retry_after,
    record_failure,
)
from app.web.templates import render
from app.security.banning.engine import (
    clear_failed_login_counters,
    evaluate_login_attempt,
)

logger = logging.getLogger(__name__)


def _coerce_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)

router = APIRouter(tags=["oidc-bff"])

_GENERIC_AUTH_FAILURE = "Identifiants invalides."
_GENERIC_AUTH_BLOCKED = "Compte temporairement bloqué suite à trop de tentatives."
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
    groups: list[str] | tuple[str, ...] | None = None,
    email: str | None = None,
    audience: str | None = None,
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


def purge_expired_oidc_sessions(db: Session) -> int:
    """Mark expired native sessions as revoked (housekeeping — JWT already invalid)."""
    now = utcnow()
    rows = (
        db.query(OidcSession)
        .filter(OidcSession.revoked.is_(False))
        .all()
    )
    purged = 0
    for row in rows:
        exp = _coerce_utc(row.expires_at)
        if exp is not None and exp <= now:
            row.revoked = True
            row.revoked_at = now
            row.revoked_by = "system"
            row.revoked_reason = "expired"
            purged += 1
    if purged:
        db.flush()
    return purged


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
    exp = _coerce_utc(row.expires_at)
    if exp is not None and exp <= utcnow():
        return True
    return False


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
    emails = {e.strip().lower() for e in (emails or set()) if e and str(e).strip()}
    usernames = {u.strip().lower() for u in (usernames or set()) if u and str(u).strip()}
    subs = {s.strip() for s in (keycloak_subs or set()) if s and str(s).strip()}
    if not emails and not usernames and not subs:
        return 0

    q = db.query(OidcSession).filter(OidcSession.revoked.is_(False))
    slug = (realm_slug or "").strip()
    if slug:
        q = q.filter(OidcSession.realm == slug)

    rows = q.all()
    now = utcnow()
    count = 0
    for row in rows:
        uname = (row.username or "").strip().lower()
        sub = (row.sub or "").strip()
        match = False
        if sub and sub in subs:
            match = True
        elif uname and (uname in usernames or uname in emails):
            match = True
        if not match:
            continue
        row.revoked = True
        row.revoked_at = now
        row.revoked_by = revoked_by
        row.revoked_reason = reason
        count += 1
    if count:
        db.flush()
    return count


def set_oidc_session_cookie(
    response: Response,
    token: str,
    settings: Settings,
) -> None:
    """
    Emit ``bastion_session`` with ``Domain=<portal parent>`` when possible so
    subdomain auth_request (transfer/webmail/…) receives the same cookie as the
    portal — mirroring oauth2-proxy ``cookie_domains``.
    """
    from app.robotic.robotic_session_cookies import portal_sso_cookie_domain

    kwargs: dict = {
        "key": settings.oidc_session_cookie_name,
        "value": token,
        "max_age": settings.oidc_session_max_age,
        "httponly": True,
        "secure": True,
        "samesite": "lax",
        "path": "/",
    }
    domain = portal_sso_cookie_domain(settings.portal_domain or "")
    if domain:
        kwargs["domain"] = domain
    response.set_cookie(**kwargs)


def clear_oidc_session_cookie(response: Response, settings: Settings) -> None:
    """Clear parent-domain cookie and any legacy host-only copy on the portal."""
    from app.robotic.robotic_session_cookies import portal_sso_cookie_domain

    name = settings.oidc_session_cookie_name
    domain = portal_sso_cookie_domain(settings.portal_domain or "")
    clear_kwargs: dict = {
        "key": name,
        "path": "/",
        "httponly": True,
        "secure": True,
        "samesite": "lax",
    }
    if domain:
        response.delete_cookie(**clear_kwargs, domain=domain)
    # Pre-cutover cookies were host-only on the portal FQDN.
    response.delete_cookie(**clear_kwargs)


def revoke_oidc_session_from_request(
    request: Request,
    db: Session,
    settings: Settings,
) -> str:
    """Revoke the ``bastion_session`` jti from the request cookie if present.

    Returns the actor string for audit (username/sub or ``unknown``).
    Does not clear the cookie — call ``clear_oidc_session_cookie`` separately.
    """
    actor = "unknown"
    cookie_name = settings.oidc_session_cookie_name
    raw = request.cookies.get(cookie_name)
    if not raw:
        return actor

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
                    options={"verify_exp": False, "verify_aud": False},
                )
                if payload.get("type") == "oidc":
                    actor = str(
                        payload.get("username") or payload.get("sub") or "unknown"
                    )
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
    return actor


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
    expected_aud = resolve_oidc_session_jwt_audience(settings)
    strict_aud = bool(getattr(settings, "oidc_session_jwt_audience_strict", False))
    if not jwt_audience_matches(payload, expected_aud, strict=strict_aud):
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
    raw_groups = payload.get("groups")
    groups: tuple[str, ...] = ()
    if isinstance(raw_groups, list):
        groups = tuple(
            str(g).strip() for g in raw_groups if isinstance(g, (str, int)) and str(g).strip()
        )
    elif isinstance(raw_groups, str) and raw_groups.strip():
        groups = tuple(g.strip() for g in raw_groups.split(",") if g.strip())
    email_raw = payload.get("email")
    email = str(email_raw).strip() if isinstance(email_raw, str) and email_raw.strip() else None
    return OidcSessionClaims(
        sub=sub,
        username=username,
        realm=realm,
        jti=jti,
        exp=exp,
        type="oidc",
        groups=groups,
        email=email,
    )


def _auth_failure_response(
    db: Session,
    *,
    request: Request,
    username: str,
    realm: str,
    reason: str,
    detail: str | None = None,
) -> None:
    """Record failure + audit, then raise generic 401 (no credential enumeration)."""
    _record_failed_attempt(
        db,
        request=request,
        username=username,
        realm=realm,
        reason=reason,
        detail=detail,
    )
    raise HTTPException(status_code=401, detail=_GENERIC_AUTH_FAILURE)


def _safe_login_rd(rd: str | None, *, portal_domain: str = "") -> str:
    from app.auth_flow import safe_post_login_rd

    return safe_post_login_rd(rd, portal_domain=portal_domain, default="/apps")


async def _resolve_session_groups(
    db: Session,
    *,
    settings: Settings,
    realm_slug: str,
    sub: str,
    claim_groups: tuple[str, ...] | list[str] | None,
) -> tuple[str, ...]:
    """Prefer OIDC token groups; fall back to Keycloak Admin API (BFF client may lack mapper)."""
    from app.oidc_bff_client import extract_groups_from_oidc_claims

    claimed = extract_groups_from_oidc_claims({"groups": list(claim_groups or ())})
    if claimed:
        return claimed

    from app.models import RealmConfig
    from app.rbac.keycloak_admin import fetch_user_groups

    realm = (
        db.query(RealmConfig)
        .filter_by(slug=realm_slug, enabled=True)
        .first()
    )
    if realm is None or not (sub or "").strip():
        return ()
    try:
        kc_groups = await fetch_user_groups(realm, sub, settings)
    except Exception:
        logger.warning(
            "oidc_login groups Admin API fallback failed realm=%s sub=%s",
            realm_slug,
            sub,
            exc_info=True,
        )
        return ()

    names: list[str] = []
    for entry in kc_groups:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("path") or entry.get("name")
        if raw is not None and str(raw).strip():
            names.append(str(raw).strip())
    return extract_groups_from_oidc_claims({"groups": names})


def _html_login_error(
    request: Request,
    settings: Settings,
    db: Session,
    *,
    rd: str,
    username: str,
    login_error: str,
    otp_required: bool = False,
    totp_setup_required: bool = False,
    attempt_id: str | None = None,
    totp_secret_display: str | None = None,
    qr_data_url: str | None = None,
    realm: str | None = None,
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
            login_panel="sso",
            form_username=username,
            otp_required=otp_required,
            totp_setup_required=totp_setup_required,
            attempt_id=attempt_id or "",
            totp_secret_display=totp_secret_display or "",
            qr_data_url=qr_data_url or "",
            **_login_surface_flags(
                request, db, settings, rd=rd, preferred_realm=realm
            ),
        ),
    )


def _html_otp_challenge(
    request: Request,
    settings: Settings,
    db: Session,
    *,
    rd: str,
    username: str,
    attempt_id: str,
    realm: str | None = None,
):
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
            form_username=username,
            otp_required=True,
            attempt_id=attempt_id,
            **_login_surface_flags(
                request, db, settings, rd=rd, preferred_realm=realm
            ),
        ),
    )


def _html_totp_setup_challenge(
    request: Request,
    settings: Settings,
    db: Session,
    *,
    rd: str,
    username: str,
    attempt_id: str,
    totp_secret_display: str | None,
    qr_data_url: str | None,
    realm: str | None = None,
    login_error: str | None = None,
):
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
            form_username=username,
            totp_setup_required=True,
            attempt_id=attempt_id,
            totp_secret_display=totp_secret_display or "",
            qr_data_url=qr_data_url or "",
            login_error=login_error,
            **_login_surface_flags(
                request, db, settings, rd=rd, preferred_realm=realm
            ),
        ),
    )


def _totp_setup_display_from_attempt(db: Session, attempt_id: str | None, settings: Settings):
    """Recover QR/secret display from a stored attempt (for error re-render)."""
    from app.models import OidcLoginAttempt
    from app.secret_crypto import decrypt_secret

    if not attempt_id:
        return "", ""
    row = db.query(OidcLoginAttempt).filter_by(attempt_id=attempt_id).first()
    if row is None:
        return "", ""
    try:
        blob = json.loads(decrypt_secret(row.otp_form_encrypted, settings))
    except Exception:
        return "", ""
    if not isinstance(blob, dict) or blob.get("kind") != "totp_setup":
        return "", ""
    return str(blob.get("secret_display") or ""), str(blob.get("qr_data_url") or "")


def _record_failed_attempt(
    db: Session,
    *,
    request: Request,
    username: str,
    realm: str,
    reason: str,
    action: str = "oidc_login_failed",
    detail: str | None = None,
) -> None:
    ip = _client_ip(request)
    _record_login_failure(ip, username)
    payload: dict[str, Any] = {"realm": realm, "reason": reason}
    if detail:
        payload["detail"] = (detail or "")[:300]
    log_action(
        db,
        actor=username or "unknown",
        action=action,
        details=payload,
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
    username: str = Form(""),
    password: str = Form(""),
    realm: str | None = Form(None),
    rd: str | None = Form(None),
    attempt_id: str | None = Form(None),
    otp_code: str | None = Form(None),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    from app.models import OidcLoginAttempt
    from app.oidc_native_session import is_oidc_native_session_enabled_for_realm

    username = (username or "").strip()
    realm_slug = (realm or "").strip() or settings.sso_portal_default_realm_slug
    attempt_id = (attempt_id or "").strip() or None
    otp_code = (otp_code or "").strip() or None
    otp_step = bool(attempt_id and otp_code)
    client_ip = _client_ip(request)
    # Presence of ``rd`` marks a classic HTML form submit (vs JSON API clients).
    html_mode = rd is not None
    safe_rd = _safe_login_rd(rd, portal_domain=settings.portal_domain or "")

    if otp_step:
        # Recover username/realm from attempt for rate-limit + gate (no enumeration).
        row = db.query(OidcLoginAttempt).filter_by(attempt_id=attempt_id).first()
        if row is not None:
            username = (row.username or username or "").strip()
            realm_slug = (row.realm or realm_slug).strip()

    if not is_oidc_native_session_enabled_for_realm(db, realm_slug, settings):
        if html_mode:
            return _html_login_error(
                request,
                settings,
                db,
                rd=safe_rd,
                username=username,
                login_error="Authentification native non activée pour ce realm.",
                realm=realm_slug,
            )
        raise HTTPException(
            status_code=403,
            detail="Authentification native non activée pour ce realm.",
        )

    # Block user when SecurityBan decided it after too many failures.
    # This is independent from the HTTP 429 hot-store throttling.
    pre = evaluate_login_attempt(
        db,
        ip=client_ip,
        username=username or "",
        success=True,
    )
    if not pre.allowed and pre.ban is not None:
        if html_mode:
            return _html_login_error(
                request,
                settings,
                db,
                rd=safe_rd,
                username=username,
                login_error=_GENERIC_AUTH_BLOCKED,
                otp_required=otp_step,
                attempt_id=attempt_id if otp_step else None,
                realm=realm_slug,
            )
        raise HTTPException(status_code=403, detail=_GENERIC_AUTH_BLOCKED)

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
                otp_required=otp_step,
                attempt_id=attempt_id,
                realm=realm_slug,
            )
        raise HTTPException(
            status_code=429,
            detail="Trop de tentatives. Réessayez plus tard.",
            headers={"Retry-After": str(max(1, int(wait)))},
        )

    try:
        if otp_step:
            if attempt_id is None or otp_code is None:
                raise InvalidCredentialsError("Identifiants incomplets")
            step = await submit_headless_otp(
                attempt_id, otp_code, settings=settings, db=db
            )
        else:
            if not username or password is None or password == "":
                raise InvalidCredentialsError("Identifiants incomplets")
            step = await start_headless_login(
                realm_slug, username, password, settings=settings, db=db
            )
    except InvalidOtpError:
        ban_eval = evaluate_login_attempt(
            db,
            ip=client_ip,
            username=username or "",
            success=False,
        )
        if html_mode:
            _record_failed_attempt(
                db,
                request=request,
                username=username,
                realm=realm_slug,
                reason="invalid_otp",
                action="oidc_login_otp_failed",
            )
            # Keep OTP / TOTP-setup form if attempt still exists.
            still = (
                db.query(OidcLoginAttempt).filter_by(attempt_id=attempt_id).first()
                if attempt_id
                else None
            )
            if still is not None:
                secret_disp, qr = _totp_setup_display_from_attempt(
                    db, attempt_id, settings
                )
                if secret_disp or qr:
                    return _html_totp_setup_challenge(
                        request,
                        settings,
                        db,
                        rd=safe_rd,
                        username=username,
                        attempt_id=attempt_id or "",
                        totp_secret_display=secret_disp,
                        qr_data_url=qr,
                        realm=realm_slug,
                        login_error=(
                            _GENERIC_AUTH_BLOCKED
                            if ban_eval.ban is not None
                            else _GENERIC_AUTH_FAILURE
                        ),
                    )
            return _html_login_error(
                request,
                settings,
                db,
                rd=safe_rd,
                username=username,
                login_error=(
                    _GENERIC_AUTH_BLOCKED
                    if ban_eval.ban is not None
                    else _GENERIC_AUTH_FAILURE
                ),
                otp_required=still is not None,
                attempt_id=attempt_id if still is not None else None,
                realm=realm_slug,
            )
        _record_failed_attempt(
            db,
            request=request,
            username=username,
            realm=realm_slug,
            reason="invalid_otp",
            action="oidc_login_otp_failed",
        )
        if ban_eval.ban is not None:
            raise HTTPException(status_code=403, detail=_GENERIC_AUTH_BLOCKED) from None
        raise HTTPException(status_code=401, detail=_GENERIC_AUTH_FAILURE) from None
    except InvalidCredentialsError:
        logger.warning(
            "oidc_login invalid_credentials realm=%s user=%s",
            realm_slug,
            username,
        )
        ban_eval = evaluate_login_attempt(
            db,
            ip=client_ip,
            username=username or "",
            success=False,
        )
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
                login_error=(
                    _GENERIC_AUTH_BLOCKED
                    if ban_eval.ban is not None
                    else _GENERIC_AUTH_FAILURE
                ),
                realm=realm_slug,
            )
        _record_failed_attempt(
            db,
            request=request,
            username=username,
            realm=realm_slug,
            reason="invalid_credentials",
        )
        if ban_eval.ban is not None:
            raise HTTPException(status_code=403, detail=_GENERIC_AUTH_BLOCKED) from None
        raise HTTPException(status_code=401, detail=_GENERIC_AUTH_FAILURE) from None
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
                login_error=_UNSUPPORTED_FLOW_LOGIN_ERROR,
                realm=realm_slug,
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
                realm=realm_slug,
            )
        raise HTTPException(status_code=503, detail=detail) from None
    except OidcBffError as exc:
        detail = str(exc) or "bff_error"
        logger.warning(
            "oidc_login BFF error realm=%s user=%s detail=%s",
            realm_slug,
            username,
            detail[:200],
        )
        if html_mode:
            _record_failed_attempt(
                db,
                request=request,
                username=username,
                realm=realm_slug,
                reason="bff_error",
                detail=detail,
            )
            return _html_login_error(
                request,
                settings,
                db,
                rd=safe_rd,
                username=username,
                login_error=_BFF_ERROR_LOGIN_ERROR,
                realm=realm_slug,
            )
        _auth_failure_response(
            db,
            request=request,
            username=username,
            realm=realm_slug,
            reason="bff_error",
            detail=detail,
        )

    if step.status == "otp_required":
        aid = step.attempt_id or ""
        db.commit()
        log_action(
            db,
            actor=username or "unknown",
            action="oidc_login_otp_required",
            details={"realm": realm_slug, "attempt_id": aid},
            ip_address=client_ip or None,
        )
        if html_mode:
            return _html_otp_challenge(
                request,
                settings,
                db,
                rd=safe_rd,
                username=username,
                attempt_id=aid,
                realm=realm_slug,
            )
        return {"status": "otp_required", "attempt_id": aid}

    if step.status == "totp_setup_required":
        from app.oidc_native_session import is_oidc_mfa_enabled_for_realm

        if not is_oidc_mfa_enabled_for_realm(db, realm_slug):
            msg = (
                "Configuration OTP demandée par l'IdP, mais le MFA est désactivé "
                "pour ce realm dans Bastion. Activez le MFA (Admin → Realms) "
                "ou retirez l'action CONFIGURE_TOTP côté Keycloak."
            )
            if html_mode:
                return _html_login_error(
                    request,
                    settings,
                    db,
                    rd=safe_rd,
                    username=username,
                    login_error=msg,
                    realm=realm_slug,
                )
            raise HTTPException(status_code=403, detail=msg)
        aid = step.attempt_id or ""
        db.commit()
        log_action(
            db,
            actor=username or "unknown",
            action="oidc_login_totp_setup_required",
            details={"realm": realm_slug, "attempt_id": aid},
            ip_address=client_ip or None,
        )
        if html_mode:
            return _html_totp_setup_challenge(
                request,
                settings,
                db,
                rd=safe_rd,
                username=username,
                attempt_id=aid,
                totp_secret_display=step.totp_secret_display,
                qr_data_url=step.qr_data_url,
                realm=realm_slug,
            )
        return {
            "status": "totp_setup_required",
            "attempt_id": aid,
            "totp_secret_display": step.totp_secret_display or "",
            "qr_data_url": step.qr_data_url or "",
        }

    tokens = step.tokens
    if tokens is None:
        if html_mode:
            return _html_login_error(
                request,
                settings,
                db,
                rd=safe_rd,
                username=username,
                login_error=_GENERIC_AUTH_FAILURE,
                realm=realm_slug,
            )
        raise HTTPException(status_code=401, detail=_GENERIC_AUTH_FAILURE)

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
                realm=realm_slug,
            )
        raise HTTPException(
            status_code=503,
            detail="Authentification temporairement indisponible.",
        )

    session_groups = await _resolve_session_groups(
        db,
        settings=settings,
        realm_slug=realm_slug,
        sub=tokens.sub,
        claim_groups=tokens.groups,
    )
    session_email = (tokens.email or "").strip() or None
    if not session_email and display_username and "@" in display_username:
        session_email = display_username

    token, jti = issue_oidc_session(
        db,
        sub=tokens.sub,
        username=display_username,
        realm=realm_slug,
        secret=secret,
        max_age=settings.oidc_session_max_age,
        groups=session_groups,
        email=session_email,
        audience=resolve_oidc_session_jwt_audience(settings),
    )
    db.commit()
    _clear_login_failures(client_ip, username)
    # Also clear SQL sliding-window counters for failed logins.
    # Otherwise a past sequence of failures can still trigger a re-ban.
    try:
        clear_failed_login_counters(
            db,
            ips={client_ip} if (client_ip or "").strip() else None,
            usernames={username} if (username or "").strip() else None,
        )
    except Exception:
        logger.exception("oidc_login sql failed-login counters clear failed")
    success_action = "oidc_login_otp_success" if otp_step else "oidc_login_success"
    log_action(
        db,
        actor=display_username or tokens.sub,
        action=success_action,
        details={"realm": realm_slug, "jti": jti, "sub": tokens.sub},
        ip_address=client_ip or None,
    )
    if html_mode:
        from app.robotic.session_cookie_hop import redirect_via_subdomain_sso_mirror

        final_rd = redirect_via_subdomain_sso_mirror(
            safe_rd, portal_domain=settings.portal_domain or ""
        )
        redirect = RedirectResponse(url=final_rd, status_code=302)
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
    actor = revoke_oidc_session_from_request(request, db, settings)
    clear_oidc_session_cookie(response, settings)
    log_action(
        db,
        actor=actor,
        action="oidc_logout",
        ip_address=_client_ip(request) or None,
    )
    return {"status": "ok"}
