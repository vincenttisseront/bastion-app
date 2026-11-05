"""End-user passkeys — passwordless sign-in with WebAuthn discoverable credentials.

Distinct from the admin second factor (``webauthn_service``): several passkeys
per user, identity keyed on the Keycloak ``sub`` within a realm, user
verification required (the passkey alone is a strong, phishing-resistant
factor), and challenges are single-use rows consumed atomically in SQL.

Bastion is the relying party (RP ID = portal host): Keycloak never sees the
ceremony, so callers must re-check the account with the Keycloak Admin API
before issuing a session (see ``app.auth.passkey_login``).
"""

from __future__ import annotations

import json
import logging
import secrets
from datetime import timedelta
from typing import Any

from fastapi import Request, Response
from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    parse_authentication_credential_json,
    parse_registration_credential_json,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.auth.oidc_native_session import is_oidc_native_session_enabled_for_realm
from app.auth.webauthn_service import RP_NAME, rp_id_and_origin
from app.models import (
    RealmConfig,
    UserPasskey,
    UserWebauthnHandle,
    WebauthnChallenge,
    utcnow,
)
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

CHALLENGE_COOKIE = "bastion_passkey_chal"
CHALLENGE_TTL_SEC = 300
PURPOSE_LOGIN = "passkey-login"
PURPOSE_REGISTER = "passkey-register"
# Browser ceremony timeout (ms) — shorter than the server-side challenge TTL.
CEREMONY_TIMEOUT_MS = 120_000
MAX_PASSKEY_NAME_LEN = 64

_SUPPORTED_ALGS = [
    COSEAlgorithmIdentifier.ECDSA_SHA_256,
    COSEAlgorithmIdentifier.EDDSA,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
]


class PasskeyError(RuntimeError):
    """Passkey ceremony refused. ``reason`` is a stable audit code (no secrets)."""

    def __init__(self, reason: str, message: str = "clé d'accès refusée") -> None:
        super().__init__(message)
        self.reason = reason


# --- Feature gate ---------------------------------------------------------


def parse_passkey_login_enabled_realms(settings: Settings) -> set[str]:
    raw = (getattr(settings, "passkey_login_enabled_realms", "") or "").strip()
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def is_passkey_login_enabled_for_realm(
    db: Session, realm: RealmConfig | None, settings: Settings
) -> bool:
    """Realm enabled + native ``bastion_session`` allowed + passkey toggle (DB or env CSV)."""
    if realm is None or not realm.enabled:
        return False
    if not is_oidc_native_session_enabled_for_realm(db, realm.slug, settings):
        return False
    if bool(realm.passkey_login_enabled):
        return True
    return (realm.slug or "").lower() in parse_passkey_login_enabled_realms(settings)


def any_passkey_login_realm(db: Session, settings: Settings) -> bool:
    """True when at least one realm accepts passkey sign-in (login page / options gate)."""
    realms = db.query(RealmConfig).filter(RealmConfig.enabled.is_(True)).all()
    return any(is_passkey_login_enabled_for_realm(db, r, settings) for r in realms)


# --- Single-use challenges ------------------------------------------------


def _subject(realm_id: int, sub: str) -> str:
    return f"{int(realm_id)}:{sub}"


def issue_challenge(db: Session, *, purpose: str, subject: str = "") -> tuple[str, bytes]:
    """Persist a fresh challenge; returns ``(challenge_id, challenge)``. Commits."""
    now = utcnow()
    # Opportunistic purge keeps the table bounded (options endpoint is public + throttled).
    db.execute(delete(WebauthnChallenge).where(WebauthnChallenge.expires_at < now))
    challenge = secrets.token_bytes(32)
    challenge_id = secrets.token_urlsafe(32)
    db.add(
        WebauthnChallenge(
            id=challenge_id,
            purpose=purpose,
            subject=subject,
            challenge=bytes_to_base64url(challenge),
            expires_at=now + timedelta(seconds=CHALLENGE_TTL_SEC),
            created_at=now,
        )
    )
    db.commit()
    return challenge_id, challenge


def consume_challenge(
    db: Session, challenge_id: str | None, *, purpose: str, subject: str = ""
) -> bytes | None:
    """Atomically mark the challenge used; ``None`` if unknown, expired, reused or mismatched."""
    cid = (challenge_id or "").strip()
    if not cid:
        return None
    now = utcnow()
    result = db.execute(
        update(WebauthnChallenge)
        .where(
            WebauthnChallenge.id == cid,
            WebauthnChallenge.purpose == purpose,
            WebauthnChallenge.subject == subject,
            WebauthnChallenge.consumed_at.is_(None),
            WebauthnChallenge.expires_at > now,
        )
        .values(consumed_at=now)
    )
    if result.rowcount != 1:
        db.rollback()
        return None
    row = db.get(WebauthnChallenge, cid)
    db.commit()
    if row is None:
        return None
    try:
        return base64url_to_bytes(row.challenge)
    except (ValueError, TypeError):
        return None


def set_challenge_cookie(response: Response, challenge_id: str) -> None:
    response.set_cookie(
        key=CHALLENGE_COOKIE,
        value=challenge_id,
        max_age=CHALLENGE_TTL_SEC,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )


def clear_challenge_cookie(response: Response) -> None:
    response.delete_cookie(
        key=CHALLENGE_COOKIE, path="/", httponly=True, secure=True, samesite="strict"
    )


def challenge_id_from_request(request: Request) -> str:
    return (request.cookies.get(CHALLENGE_COOKIE) or "").strip()


# --- User handles ---------------------------------------------------------


def get_or_create_user_handle(db: Session, realm_id: int, sub: str) -> bytes:
    """Random 32-byte WebAuthn ``user.id`` for this identity (created once)."""
    row = (
        db.query(UserWebauthnHandle)
        .filter_by(realm_id=realm_id, keycloak_sub=sub)
        .first()
    )
    if row is None:
        row = UserWebauthnHandle(
            realm_id=realm_id,
            keycloak_sub=sub,
            user_handle=bytes_to_base64url(secrets.token_bytes(32)),
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError:
            # Concurrent first registration for the same identity.
            db.rollback()
            row = (
                db.query(UserWebauthnHandle)
                .filter_by(realm_id=realm_id, keycloak_sub=sub)
                .one()
            )
    return base64url_to_bytes(row.user_handle)


def _user_handle_matches(db: Session, passkey: UserPasskey, user_handle: bytes | None) -> bool:
    if not user_handle:
        return False
    row = (
        db.query(UserWebauthnHandle)
        .filter_by(realm_id=passkey.realm_id, keycloak_sub=passkey.keycloak_sub)
        .first()
    )
    if row is None:
        return False
    return secrets.compare_digest(row.user_handle, bytes_to_base64url(user_handle))


# --- Queries --------------------------------------------------------------


def list_user_passkeys(db: Session, realm_id: int, sub: str) -> list[UserPasskey]:
    return (
        db.query(UserPasskey)
        .filter_by(realm_id=realm_id, keycloak_sub=sub, revoked=False)
        .order_by(UserPasskey.created_at.asc(), UserPasskey.id.asc())
        .all()
    )


def _active_passkey_by_credential_id(db: Session, credential_id: bytes) -> UserPasskey | None:
    return (
        db.query(UserPasskey)
        .filter_by(credential_id=bytes_to_base64url(credential_id), revoked=False)
        .first()
    )


def revoke_passkey(
    db: Session, passkey: UserPasskey, *, revoked_by: str, reason: str
) -> None:
    """Soft-revoke (kept for audit). Caller commits."""
    passkey.revoked = True
    passkey.revoked_at = utcnow()
    passkey.revoked_by = (revoked_by or "unknown")[:200]
    passkey.revoked_reason = (reason or "")[:200]


# --- Sign-in (usernameless) ----------------------------------------------


def build_login_options(db: Session, settings: Settings) -> tuple[dict[str, Any], str]:
    """Options for ``navigator.credentials.get`` (empty allowCredentials → discoverable)."""
    rp_id, _origin = rp_id_and_origin(settings)
    challenge_id, challenge = issue_challenge(db, purpose=PURPOSE_LOGIN)
    options = generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge,
        timeout=CEREMONY_TIMEOUT_MS,
        allow_credentials=[],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(options)), challenge_id


def verify_login_assertion(
    db: Session,
    settings: Settings,
    *,
    credential: dict[str, Any] | str,
    challenge_id: str | None,
    client_ip: str | None = None,
) -> UserPasskey:
    """Verify a usernameless assertion and return the matching passkey row.

    Order matters: the challenge is burnt first, so a failed attempt can never
    be retried against the same challenge.
    """
    expected_challenge = consume_challenge(db, challenge_id, purpose=PURPOSE_LOGIN)
    if expected_challenge is None:
        raise PasskeyError("challenge_invalid")
    try:
        parsed = parse_authentication_credential_json(credential)
    except Exception as exc:
        raise PasskeyError("malformed_credential") from exc

    passkey = _active_passkey_by_credential_id(db, parsed.raw_id)
    if passkey is None:
        raise PasskeyError("unknown_credential")
    if not _user_handle_matches(db, passkey, parsed.response.user_handle):
        raise PasskeyError("user_handle_mismatch")

    rp_id, origin = rp_id_and_origin(settings)
    try:
        verified = verify_authentication_response(
            credential=parsed,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(passkey.public_key),
            # Counter compared below, after the signature is proven genuine,
            # so a regression is reported as such (clone) and not as a bad signature.
            credential_current_sign_count=0,
            require_user_verification=True,
        )
    except Exception as exc:
        logger.warning("passkey assertion verify failed: %s", type(exc).__name__)
        raise PasskeyError("assertion_invalid") from exc

    stored = int(passkey.sign_count or 0)
    received = int(verified.new_sign_count or 0)
    if (received > 0 or stored > 0) and received <= stored:
        logger.warning(
            "passkey sign count regression id=%s stored=%s received=%s",
            passkey.id,
            stored,
            received,
        )
        raise PasskeyError("sign_count_regression")

    passkey.sign_count = received
    passkey.backup_state = bool(verified.credential_backed_up)
    passkey.last_used_at = utcnow()
    passkey.last_used_ip = (client_ip or "")[:64] or None
    db.commit()
    db.refresh(passkey)
    return passkey


# --- Registration (authenticated user) -----------------------------------


def build_registration_options(
    db: Session,
    settings: Settings,
    *,
    realm: RealmConfig,
    sub: str,
    username: str,
    display_name: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Options for ``navigator.credentials.create`` — resident key + UV required."""
    rp_id, _origin = rp_id_and_origin(settings)
    user_handle = get_or_create_user_handle(db, realm.id, sub)
    existing = list_user_passkeys(db, realm.id, sub)
    challenge_id, challenge = issue_challenge(
        db, purpose=PURPOSE_REGISTER, subject=_subject(realm.id, sub)
    )
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_name=username,
        user_id=user_handle,
        user_display_name=display_name or username,
        challenge=challenge,
        timeout=CEREMONY_TIMEOUT_MS,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            require_resident_key=True,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(pk.credential_id),
                type=PublicKeyCredentialType.PUBLIC_KEY,
            )
            for pk in existing
        ],
        supported_pub_key_algs=_SUPPORTED_ALGS,
    )
    return json.loads(options_to_json(options)), challenge_id


def _transports_from(credential: dict[str, Any] | str) -> list[str] | None:
    data = credential
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            return None
    if not isinstance(data, dict):
        return None
    resp = data.get("response") or {}
    raw = resp.get("transports") if isinstance(resp, dict) else None
    raw = raw if raw is not None else data.get("transports")
    if not isinstance(raw, list):
        return None
    return [str(t)[:32] for t in raw if isinstance(t, str)][:8] or None


def verify_and_store_registration(
    db: Session,
    settings: Settings,
    *,
    realm: RealmConfig,
    sub: str,
    username: str | None,
    credential: dict[str, Any] | str,
    challenge_id: str | None,
    name: str | None = None,
) -> UserPasskey:
    expected_challenge = consume_challenge(
        db, challenge_id, purpose=PURPOSE_REGISTER, subject=_subject(realm.id, sub)
    )
    if expected_challenge is None:
        raise PasskeyError("challenge_invalid")
    try:
        parsed = parse_registration_credential_json(credential)
    except Exception as exc:
        raise PasskeyError("malformed_credential") from exc

    rp_id, origin = rp_id_and_origin(settings)
    try:
        verified = verify_registration_response(
            credential=parsed,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
            supported_pub_key_algs=_SUPPORTED_ALGS,
        )
    except Exception as exc:
        logger.warning("passkey registration verify failed: %s", type(exc).__name__)
        raise PasskeyError("registration_invalid") from exc

    credential_id = bytes_to_base64url(verified.credential_id)
    if db.query(UserPasskey.id).filter_by(credential_id=credential_id).first() is not None:
        raise PasskeyError("already_registered")

    label = (name or "").strip()[:MAX_PASSKEY_NAME_LEN] or None
    row = UserPasskey(
        realm_id=realm.id,
        keycloak_sub=sub,
        username=(username or "").strip() or None,
        credential_id=credential_id,
        public_key=bytes_to_base64url(verified.credential_public_key),
        sign_count=int(verified.sign_count or 0),
        transports=_transports_from(credential),
        aaguid=(verified.aaguid or None),
        backup_eligible=str(getattr(verified.credential_device_type, "value", ""))
        == "multi_device",
        backup_state=bool(verified.credential_backed_up),
        name=label,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise PasskeyError("already_registered") from exc
    db.refresh(row)
    logger.info("passkey registered id=%s realm=%s", row.id, realm.slug)
    return row
