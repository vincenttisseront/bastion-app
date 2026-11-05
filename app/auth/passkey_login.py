"""Passwordless sign-in with a passkey → native ``bastion_session``.

Flow (JSON, called by the login page script):

1. ``POST /auth/passkey/options`` — CSRF + IP throttle → request options with an
   empty ``allowCredentials`` (discoverable credential) + single-use challenge
   cookie.
2. ``POST /auth/passkey/verify`` — assertion verified (user verification
   required) → the account is re-checked with the Keycloak Admin API (exists,
   enabled, no pending required action, fresh groups) → shared
   ``finalize_native_login``.

Keycloak does not run this login: it creates no Keycloak session (``kc_sid``
absent) and its brute-force / required-action logic is not applied, hence the
explicit Admin API checks, which fail closed when the API is unreachable.
SQL work runs in the threadpool; only the Keycloak calls stay on the loop.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.audit import log_action
from app.auth.flow import safe_post_login_rd
from app.auth.oidc_bff import (
    NativeLoginIdentity,
    finalize_native_login,
    groups_from_keycloak_admin_entries,
)
from app.auth.oidc_bff_config_service import resolve_oidc_session_jwt_secret
from app.auth.passkey_service import (
    PasskeyError,
    any_passkey_login_realm,
    build_login_options,
    challenge_id_from_request,
    clear_challenge_cookie,
    is_passkey_login_enabled_for_realm,
    set_challenge_cookie,
    verify_login_assertion,
)
from app.database import get_db
from app.models import BastionAccount, RealmConfig
from app.request_client_ip import client_ip_from_request
from app.security.banning.engine import evaluate_login_attempt
from app.sso_settings import Settings, get_settings
from app.testing_framework.throttle import (
    clear_failures,
    failure_block_retry_after,
    record_failure,
)
from app.web.csrf import portal_signing_secret, verify_csrf_token
from app.web.openapi_responses import RESP_401, RESP_403, RESP_503

logger = logging.getLogger(__name__)

router = APIRouter(tags=["passkey"])

# Process-local throttles (the SQL ban engine is the cross-worker layer).
_RATE_OPTIONS = "passkey_options"
OPTIONS_MAX_PER_WINDOW = 30
_RATE_VERIFY = "passkey_login"
VERIFY_MAX_FAILURES = 10
RATE_WINDOW_SECONDS = 60.0

_GENERIC_FAILURE = "Clé d'accès non reconnue."
_BLOCKED = "Compte temporairement bloqué suite à trop de tentatives."
_TOO_MANY = "Trop de tentatives. Réessayez plus tard."
_DISABLED = "Connexion par clé d'accès non activée."
_CSRF_EXPIRED = "Session expirée — rechargez la page et réessayez."
_AUTH_UNAVAILABLE = "Authentification temporairement indisponible."
_IDP_UNAVAILABLE = (
    "Vérification du compte impossible pour le moment — "
    "connectez-vous avec votre mot de passe."
)
_ACTION_REQUIRED = (
    "Une action est requise sur votre compte — connectez-vous avec votre mot de passe."
)

_AUDIT_FAILED = "oidc_login_passkey_failed"
_AUDIT_SUCCESS = "oidc_login_passkey_success"


class PasskeyVerifyBody(BaseModel):
    credential: dict[str, Any]
    rd: str | None = Field(default=None, max_length=2048)


class _Refused(Exception):
    def __init__(self, status: int, message: str, headers: dict[str, str] | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.headers = headers


@dataclass(slots=True)
class _Verified:
    client_ip: str
    passkey_id: int
    realm: RealmConfig
    sub: str
    username: str | None
    secret: str
    safe_rd: str


def _refusal_response(exc: _Refused) -> JSONResponse:
    response = JSONResponse(
        {"detail": exc.message}, status_code=exc.status, headers=exc.headers
    )
    clear_challenge_cookie(response)
    return response


def _audit(
    db: Session, action: str, *, ip: str, actor: str | None, details: dict[str, Any]
) -> None:
    log_action(
        db,
        actor=actor or "unknown",
        action=action,
        details=details,
        ip_address=ip or None,
    )


def _failure(
    db: Session,
    *,
    ip: str,
    reason: str,
    username: str | None = None,
    realm_slug: str | None = None,
) -> _Refused:
    """Count a failed sign-in (process throttle + SQL ban engine) and audit it."""
    record_failure(_RATE_VERIFY, ip or "unknown", window_seconds=RATE_WINDOW_SECONDS)
    ban_eval = evaluate_login_attempt(db, ip=ip, username=username or "", success=False)
    details: dict[str, Any] = {"reason": reason}
    if realm_slug:
        details["realm"] = realm_slug
    _audit(db, _AUDIT_FAILED, ip=ip, actor=username, details=details)
    logger.warning("passkey login refused reason=%s", reason)
    if ban_eval.ban is not None:
        return _Refused(403, _BLOCKED)
    return _Refused(401, _GENERIC_FAILURE)


def _require_csrf(request: Request, settings: Settings) -> None:
    if not verify_csrf_token(request, portal_signing_secret(settings), ""):
        raise _Refused(403, _CSRF_EXPIRED)


def _require_not_banned(db: Session, ip: str, username: str | None = None) -> None:
    pre = evaluate_login_attempt(db, ip=ip, username=username or "", success=True)
    if not pre.allowed and pre.ban is not None:
        raise _Refused(403, _BLOCKED)


@router.post("/auth/passkey/options", responses=RESP_403)
def passkey_login_options(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    """Challenge for ``navigator.credentials.get`` (header ``X-CSRF-Token``)."""
    ip = client_ip_from_request(request)
    try:
        _require_csrf(request, settings)
        key = ip or "unknown"
        wait = failure_block_retry_after(
            _RATE_OPTIONS,
            key,
            max_failures=OPTIONS_MAX_PER_WINDOW,
            window_seconds=RATE_WINDOW_SECONDS,
        )
        if wait is not None:
            raise _Refused(429, _TOO_MANY, headers={"Retry-After": str(max(1, int(wait)))})
        # Every call counts: the endpoint writes a row, so it is bounded per IP.
        record_failure(_RATE_OPTIONS, key, window_seconds=RATE_WINDOW_SECONDS)
        _require_not_banned(db, ip)
        if not any_passkey_login_realm(db, settings):
            raise _Refused(404, _DISABLED)
    except _Refused as exc:
        return _refusal_response(exc)
    options, challenge_id = build_login_options(db, settings)
    response = JSONResponse({"options": options})
    set_challenge_cookie(response, challenge_id)
    return response


def _verify_stage(
    request: Request, settings: Settings, db: Session, body: PasskeyVerifyBody
) -> _Verified:
    ip = client_ip_from_request(request)
    _require_csrf(request, settings)
    wait = failure_block_retry_after(
        _RATE_VERIFY,
        ip or "unknown",
        max_failures=VERIFY_MAX_FAILURES,
        window_seconds=RATE_WINDOW_SECONDS,
    )
    if wait is not None:
        raise _Refused(429, _TOO_MANY, headers={"Retry-After": str(max(1, int(wait)))})
    _require_not_banned(db, ip)

    try:
        passkey = verify_login_assertion(
            db,
            settings,
            credential=body.credential,
            challenge_id=challenge_id_from_request(request),
            client_ip=ip,
        )
    except PasskeyError as exc:
        raise _failure(db, ip=ip, reason=exc.reason) from None

    realm = passkey.realm
    if not is_passkey_login_enabled_for_realm(db, realm, settings):
        _audit(
            db,
            _AUDIT_FAILED,
            ip=ip,
            actor=passkey.username,
            details={"reason": "realm_disabled", "realm": getattr(realm, "slug", None)},
        )
        raise _Refused(403, _DISABLED)
    _require_not_banned(db, ip, passkey.username)

    secret = resolve_oidc_session_jwt_secret(db, settings)
    if not secret:
        raise _Refused(503, _AUTH_UNAVAILABLE)
    return _Verified(
        client_ip=ip,
        passkey_id=passkey.id,
        realm=realm,
        sub=passkey.keycloak_sub,
        username=passkey.username,
        secret=secret,
        safe_rd=safe_post_login_rd(
            body.rd, portal_domain=settings.portal_domain or "", default="/apps"
        ),
    )


async def _load_keycloak_account(
    stage: _Verified, settings: Settings
) -> tuple[dict[str, Any] | None, list[Any]]:
    """Fresh account + groups from the Admin API. Raises on any API failure."""
    from app.rbac.keycloak_admin import fetch_keycloak_user, fetch_user_groups

    kc_user = await fetch_keycloak_user(stage.realm, stage.sub, settings)
    if kc_user is None:
        return None, []
    groups = await fetch_user_groups(stage.realm, stage.sub, settings)
    return kc_user, groups


def _bastion_account_disabled(db: Session, sub: str) -> bool:
    return (
        db.query(BastionAccount.id)
        .filter(
            BastionAccount.keycloak_user_id == sub,
            BastionAccount.disabled_at.isnot(None),
        )
        .first()
        is not None
    )


def _finalize_stage(
    db: Session,
    settings: Settings,
    stage: _Verified,
    kc_user: dict[str, Any] | None,
    kc_groups: list[Any],
) -> JSONResponse:
    slug = stage.realm.slug
    if kc_user is None:
        raise _failure(
            db, ip=stage.client_ip, reason="user_not_found", username=stage.username, realm_slug=slug
        )
    if not kc_user.get("enabled", False):
        raise _failure(
            db, ip=stage.client_ip, reason="user_disabled", username=stage.username, realm_slug=slug
        )
    if _bastion_account_disabled(db, stage.sub):
        raise _failure(
            db,
            ip=stage.client_ip,
            reason="account_disabled",
            username=stage.username,
            realm_slug=slug,
        )
    if kc_user.get("requiredActions"):
        # e.g. UPDATE_PASSWORD after an admin reset: the password flow must run.
        _audit(
            db,
            _AUDIT_FAILED,
            ip=stage.client_ip,
            actor=stage.username,
            details={"reason": "required_action", "realm": slug},
        )
        raise _Refused(401, _ACTION_REQUIRED)

    username = (str(kc_user.get("username") or "").strip() or stage.username) or None
    email = str(kc_user.get("email") or "").strip() or None
    if not email and username and "@" in username:
        email = username

    from app.models import UserPasskey

    passkey = db.get(UserPasskey, stage.passkey_id)
    if passkey is not None and username and passkey.username != username:
        passkey.username = username  # renamed in Keycloak

    identity = NativeLoginIdentity(
        sub=stage.sub,
        username=username,
        email=email,
        groups=groups_from_keycloak_admin_entries(kc_groups),
        realm_slug=slug,
        kc_sid=None,
    )
    response = finalize_native_login(
        db,
        settings,
        identity,
        secret=stage.secret,
        client_ip=stage.client_ip,
        login_username=username or "",
        safe_rd=stage.safe_rd,
        html_mode=False,
        audit_action=_AUDIT_SUCCESS,
        audit_details={"auth_method": "passkey", "passkey_id": stage.passkey_id},
        include_redirect=True,
    )
    clear_failures(_RATE_VERIFY, stage.client_ip or "unknown")
    clear_challenge_cookie(response)
    return response


def _idp_unavailable(db: Session, stage: _Verified) -> _Refused:
    _audit(
        db,
        _AUDIT_FAILED,
        ip=stage.client_ip,
        actor=stage.username,
        details={"reason": "idp_unavailable", "realm": stage.realm.slug},
    )
    return _Refused(503, _IDP_UNAVAILABLE)


@router.post("/auth/passkey/verify", responses=RESP_401 | RESP_403 | RESP_503)
async def passkey_login_verify(
    request: Request,
    body: PasskeyVerifyBody,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    """Verify the assertion and open a native session (JSON ``{status, redirect}``)."""
    try:
        stage = await run_in_threadpool(_verify_stage, request, settings, db, body)
        try:
            kc_user, kc_groups = await _load_keycloak_account(stage, settings)
        except Exception:
            logger.warning(
                "passkey login: Keycloak Admin API check failed realm=%s",
                stage.realm.slug,
                exc_info=True,
            )
            raise await run_in_threadpool(_idp_unavailable, db, stage) from None
        return await run_in_threadpool(
            _finalize_stage, db, settings, stage, kc_user, kc_groups
        )
    except _Refused as exc:
        return _refusal_response(exc)
