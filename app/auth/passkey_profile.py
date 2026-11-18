"""Self-service passkey enrolment from the profile page (lot 2).

The owner of a new passkey is taken from the validated native ``bastion_session``
(``sub`` + realm), never from a form field. Enrolment requires a *recent* login
(``REAUTH_WINDOW``): a passkey replaces password + OTP at the next sign-in, so a
stolen long-lived session must not be enough to plant a persistent credential.

Guards, in order (all fail closed):

- break-glass sessions and ``@breakglass.local`` identities are refused — the
  reserved domain never gets a passwordless credential;
- the realm must accept passkey sign-in (same gate as ``/auth/passkey/*``);
- the session must have been issued less than ``REAUTH_WINDOW`` ago.

Routes are JSON (``X-CSRF-Token`` header) except deletion, which is a form post
with a flash redirect like the other profile actions. SQL runs in the threadpool
(sync handlers).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth.oidc_bff import OidcSessionClaims
from app.auth.passkey_service import (
    MAX_PASSKEY_NAME_LEN,
    PasskeyError,
    build_registration_options,
    challenge_id_from_request,
    clear_challenge_cookie,
    is_passkey_login_enabled_for_realm,
    list_user_passkeys,
    revoke_passkey,
    set_challenge_cookie,
    verify_and_store_registration,
)
from app.database import get_db
from app.models import OidcSession, RealmConfig, UserPasskey, utcnow
from app.realm_lookup import find_realm
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings
from app.testing_framework.throttle import failure_block_retry_after, record_failure
from app.web.csrf import portal_signing_secret, verify_csrf_token
from app.web.flash import flash_redirect
from app.web.openapi_responses import RESP_401, RESP_403, RESP_404
from app.web.user_context import UserContext, is_breakglass_email, require_user_enriched

logger = logging.getLogger(__name__)

router = APIRouter(tags=["passkey"], dependencies=[Depends(require_user_enriched)])

# A passkey is a primary factor: only a fresh login may enrol one.
REAUTH_WINDOW = timedelta(minutes=10)
MAX_PASSKEYS_PER_USER = 10
_RATE_REGISTER = "passkey_register"
REGISTER_MAX_PER_WINDOW = 20
RATE_WINDOW_SECONDS = 60.0

_PATH_SECURITY = "/profile#section-passkeys"

_CSRF_INVALID = "Jeton CSRF invalide"
_UNAVAILABLE = "Les clés d'accès ne sont pas disponibles pour ce compte."
_REAUTH = "Pour des raisons de sécurité, reconnectez-vous puis ajoutez la clé dans les 10 minutes."
_TOO_MANY = "Trop de tentatives. Réessayez plus tard."
_LIMIT = "Nombre maximal de clés d'accès atteint."
_REFUSED = "Clé d'accès refusée — réessayez."
_DUPLICATE = "Cette clé d'accès est déjà enregistrée."

_AUDIT_REGISTERED = "profile.passkey_registered"
_AUDIT_REMOVED = "profile.passkey_removed"


class PasskeyRegisterBody(BaseModel):
    credential: dict[str, Any]
    name: str | None = Field(default=None, max_length=MAX_PASSKEY_NAME_LEN * 2)


class _Refused(Exception):
    def __init__(self, status: int, message: str, *, reauth: bool = False):
        super().__init__(message)
        self.status = status
        self.message = message
        self.reauth = reauth


@dataclass(slots=True)
class PasskeyOwner:
    """Identity a passkey is (or would be) bound to."""

    realm: RealmConfig
    sub: str
    username: str
    display_name: str
    claims: OidcSessionClaims


def _current_claims(request: Request, db: Session, settings: Settings) -> OidcSessionClaims | None:
    from app.web.profile_security_service import current_native_session

    return current_native_session(request, db, settings)


def _identity_is_reserved(user: UserContext, claims: OidcSessionClaims | None) -> bool:
    if user.is_breakglass or (user.auth_source or "") == "breakglass":
        return True
    values = [user.email, user.username]
    if claims is not None:
        values += [claims.email, claims.username]
    return any(is_breakglass_email(v) for v in values)


def resolve_passkey_owner(
    request: Request, db: Session, settings: Settings, user: UserContext
) -> PasskeyOwner | None:
    """Owner for the profile passkey section, or ``None`` when unavailable.

    Does not check the re-authentication window (listing is always allowed).
    """
    claims = _current_claims(request, db, settings)
    if claims is None or _identity_is_reserved(user, claims):
        return None
    kc_id = (user.keycloak_user_id or "").strip()
    if kc_id and kc_id != claims.sub:
        # Headers and native cookie disagree — never guess which one is right.
        logger.warning("passkey profile: identity mismatch between session and headers")
        return None
    realm = find_realm(db, claims.realm)
    if realm is None:
        return None
    if not is_passkey_login_enabled_for_realm(db, realm, settings):
        return None
    username = (claims.username or user.username or claims.email or "").strip()
    if not username:
        return None
    return PasskeyOwner(
        realm=realm,
        sub=claims.sub,
        username=username,
        display_name=(user.display_name or username).strip() or username,
        claims=claims,
    )


def session_is_recent(db: Session, claims: OidcSessionClaims) -> bool:
    row = db.query(OidcSession.issued_at).filter_by(jti=claims.jti).first()
    if row is None or row[0] is None:
        return False
    issued = row[0]
    now = utcnow()
    if issued.tzinfo is None and now.tzinfo is not None:
        issued = issued.replace(tzinfo=now.tzinfo)
    return now - issued <= REAUTH_WINDOW


def passkey_profile_context(
    request: Request, db: Session, settings: Settings, user: UserContext
) -> dict[str, Any]:
    """Template context for the profile passkey section."""
    owner = resolve_passkey_owner(request, db, settings, user)
    if owner is None:
        return {"passkeys_available": False, "passkeys": []}
    rows = list_user_passkeys(db, owner.realm.id, owner.sub)
    return {
        "passkeys_available": True,
        "passkeys": [_serialize(pk) for pk in rows],
        "passkeys_limit_reached": len(rows) >= MAX_PASSKEYS_PER_USER,
    }


def _serialize(pk: UserPasskey) -> dict[str, Any]:
    return {
        "id": pk.id,
        "name": pk.name or "Clé d'accès",
        "synced": bool(pk.backup_eligible),
        "created_at": pk.created_at,
        "last_used_at": pk.last_used_at,
    }


def _require_owner(
    request: Request, db: Session, settings: Settings, user: UserContext
) -> PasskeyOwner:
    if not verify_csrf_token(request, portal_signing_secret(settings), ""):
        raise _Refused(403, _CSRF_INVALID)
    owner = resolve_passkey_owner(request, db, settings, user)
    if owner is None:
        raise _Refused(403, _UNAVAILABLE)
    if not session_is_recent(db, owner.claims):
        raise _Refused(401, _REAUTH, reauth=True)
    return owner


def _refusal(exc: _Refused) -> JSONResponse:
    body: dict[str, Any] = {"detail": exc.message}
    if exc.reauth:
        body["reauth"] = True
    response = JSONResponse(body, status_code=exc.status)
    clear_challenge_cookie(response)
    return response


def _throttle(owner: PasskeyOwner) -> None:
    key = f"{owner.realm.id}:{owner.sub}"
    wait = failure_block_retry_after(
        _RATE_REGISTER,
        key,
        max_failures=REGISTER_MAX_PER_WINDOW,
        window_seconds=RATE_WINDOW_SECONDS,
    )
    if wait is not None:
        raise _Refused(429, _TOO_MANY)
    record_failure(_RATE_REGISTER, key, window_seconds=RATE_WINDOW_SECONDS)


@router.post("/profile/passkeys/register/options", responses=RESP_401 | RESP_403)
def passkey_register_options(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    """Options for ``navigator.credentials.create`` (header ``X-CSRF-Token``)."""
    try:
        owner = _require_owner(request, db, settings, user)
        _throttle(owner)
        if len(list_user_passkeys(db, owner.realm.id, owner.sub)) >= MAX_PASSKEYS_PER_USER:
            raise _Refused(409, _LIMIT)
    except _Refused as exc:
        return _refusal(exc)
    options, challenge_id = build_registration_options(
        db,
        settings,
        realm=owner.realm,
        sub=owner.sub,
        username=owner.username,
        display_name=owner.display_name,
    )
    response = JSONResponse({"options": options})
    set_challenge_cookie(response, challenge_id)
    return response


@router.post("/profile/passkeys/register/verify", responses=RESP_401 | RESP_403)
def passkey_register_verify(
    request: Request,
    body: PasskeyRegisterBody,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    """Store the new passkey after verifying the attestation (UV required)."""
    ip = client_ip_from_request(request)
    try:
        owner = _require_owner(request, db, settings, user)
        if len(list_user_passkeys(db, owner.realm.id, owner.sub)) >= MAX_PASSKEYS_PER_USER:
            raise _Refused(409, _LIMIT)
        try:
            row = verify_and_store_registration(
                db,
                settings,
                realm=owner.realm,
                sub=owner.sub,
                username=owner.username,
                credential=body.credential,
                challenge_id=challenge_id_from_request(request),
                name=body.name,
            )
        except PasskeyError as exc:
            logger.warning("passkey registration refused reason=%s", exc.reason)
            raise _Refused(
                409 if exc.reason == "already_registered" else 400,
                _DUPLICATE if exc.reason == "already_registered" else _REFUSED,
            ) from None
    except _Refused as exc:
        return _refusal(exc)
    log_action(
        db,
        actor=owner.username,
        action=_AUDIT_REGISTERED,
        target=f"passkey:{row.id}",
        details={"realm": owner.realm.slug, "sub": owner.sub, "synced": bool(row.backup_eligible)},
        ip_address=ip or None,
    )
    response = JSONResponse({"status": "ok", "passkey": {"id": row.id, "name": row.name}})
    clear_challenge_cookie(response)
    return response


@router.post("/profile/passkeys/{passkey_id}/delete", responses=RESP_403 | RESP_404)
def passkey_delete(
    passkey_id: int,
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    """Revoke one of the caller's passkeys (soft revocation, kept for audit)."""
    secret = portal_signing_secret(settings)
    response = RedirectResponse(url=_PATH_SECURITY, status_code=302)
    if not verify_csrf_token(request, secret, csrf_token):
        flash_redirect(response, _CSRF_INVALID, "error", secret)
        return response
    owner = resolve_passkey_owner(request, db, settings, user)
    passkey = db.get(UserPasskey, passkey_id)
    if (
        owner is None
        or passkey is None
        or passkey.revoked
        or passkey.realm_id != owner.realm.id
        or passkey.keycloak_sub != owner.sub
    ):
        flash_redirect(response, "Clé d'accès introuvable.", "error", secret)
        return response
    revoke_passkey(db, passkey, revoked_by=owner.username, reason="owner")
    db.commit()
    log_action(
        db,
        actor=owner.username,
        action=_AUDIT_REMOVED,
        target=f"passkey:{passkey.id}",
        details={"realm": owner.realm.slug, "sub": owner.sub},
        ip_address=client_ip_from_request(request) or None,
    )
    flash_redirect(response, "Clé d'accès supprimée.", "success", secret)
    return response
