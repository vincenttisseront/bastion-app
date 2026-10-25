"""Admin WebAuthn / Passkeys (py_webauthn) — COSE public keys as Base64URL."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import Any

from fastapi import Request, Response
from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.auth.totp_service import get_or_create_credential
from app.models import AdminMfaCredential, utcnow
from app.sso_settings import Settings
from app.web.csrf import portal_signing_secret

logger = logging.getLogger(__name__)

CHALLENGE_COOKIE = "bastion_webauthn_chal"
CHALLENGE_TTL_SEC = 300
RP_NAME = "Bastion Portal"


class WebAuthnError(RuntimeError):
    """WebAuthn registration/assertion failure (no secrets in message)."""


def _norm_email(email: str) -> str:
    return (email or "").strip().lower()


def rp_id_and_origin(settings: Settings) -> tuple[str, str]:
    """Derive WebAuthn RP ID + origin from portal FQDN."""
    host = (settings.portal_domain or "portal.example.com").strip().lower()
    host = host.split("/")[0].split(":")[0]
    if not host:
        host = "portal.example.com"
    # Local/dev may use http; production expects https.
    scheme = "http" if host in ("localhost", "127.0.0.1") else "https"
    return host, f"{scheme}://{host}"


def _user_handle(email: str) -> bytes:
    # Stable opaque user id (max 64 bytes for WebAuthn).
    return hashlib.sha256(_norm_email(email).encode("utf-8")).digest()


def _sign_challenge(secret: str, email: str, purpose: str, challenge_b64: str, exp: int) -> str:
    msg = f"{_norm_email(email)}|{purpose}|{challenge_b64}|{exp}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def stash_challenge(
    response: Response,
    settings: Settings,
    *,
    user_email: str,
    purpose: str,
    challenge: bytes,
) -> None:
    secret = portal_signing_secret(settings)
    exp = int(time.time()) + CHALLENGE_TTL_SEC
    chal_b64 = bytes_to_base64url(challenge)
    sig = _sign_challenge(secret, user_email, purpose, chal_b64, exp)
    value = f"{_norm_email(user_email)}|{purpose}|{chal_b64}|{exp}|{sig}"
    response.set_cookie(
        key=CHALLENGE_COOKIE,
        value=value,
        httponly=True,
        secure=bool(getattr(settings, "is_production", False)),
        samesite="lax",
        max_age=CHALLENGE_TTL_SEC,
        path="/",
    )


def pop_challenge(
    request: Request,
    settings: Settings,
    *,
    user_email: str,
    purpose: str,
) -> bytes | None:
    raw = (request.cookies.get(CHALLENGE_COOKIE) or "").strip()
    if not raw:
        return None
    try:
        email, purp, chal_b64, exp_s, sig = raw.split("|", 4)
    except ValueError:
        return None
    if _norm_email(email) != _norm_email(user_email) or purp != purpose:
        return None
    try:
        exp = int(exp_s)
    except ValueError:
        return None
    if time.time() > exp:
        return None
    secret = portal_signing_secret(settings)
    expected = _sign_challenge(secret, email, purp, chal_b64, exp)
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        return base64url_to_bytes(chal_b64)
    except Exception:
        return None


def clear_challenge_cookie(response: Response) -> None:
    response.delete_cookie(CHALLENGE_COOKIE, path="/")


def build_registration_options(
    settings: Settings, user_email: str
) -> tuple[dict[str, Any], bytes]:
    rp_id, _origin = rp_id_and_origin(settings)
    email = _norm_email(user_email)
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_name=email,
        user_id=_user_handle(email),
        user_display_name=email,
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.EDDSA,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        attestation=AttestationConveyancePreference.NONE,
    )
    return json.loads(options_to_json(options)), options.challenge


def verify_and_store_registration(
    db: Session,
    settings: Settings,
    *,
    user_email: str,
    credential: dict[str, Any] | str,
    expected_challenge: bytes,
) -> AdminMfaCredential:
    rp_id, origin = rp_id_and_origin(settings)
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=False,
        )
    except Exception as exc:
        logger.warning("webauthn registration verify failed: %s", type(exc).__name__)
        raise WebAuthnError("attestation WebAuthn invalide") from exc

    row = get_or_create_credential(db, user_email)
    row.webauthn_credential_id = bytes_to_base64url(verified.credential_id)
    row.webauthn_public_key = bytes_to_base64url(verified.credential_public_key)
    row.webauthn_sign_count = int(verified.sign_count or 0)
    # Store transports list if present on credential JSON
    if isinstance(credential, dict):
        resp = credential.get("response") or {}
        tr = resp.get("transports") or credential.get("transports")
        if isinstance(tr, list):
            row.webauthn_transports = tr
    row.webauthn_enabled = True
    row.updated_at = utcnow()
    db.commit()
    db.refresh(row)
    logger.info("webauthn: registered credential for %s", _norm_email(user_email))
    return row


def _get_credential(db: Session, user_email: str) -> AdminMfaCredential | None:
    email = _norm_email(user_email)
    if not email:
        return None
    return (
        db.query(AdminMfaCredential)
        .filter(AdminMfaCredential.user_email == email)
        .first()
    )


def build_authentication_options(
    db: Session, settings: Settings, user_email: str
) -> tuple[dict[str, Any], bytes]:
    row = _get_credential(db, user_email)
    if (
        row is None
        or not row.webauthn_enabled
        or not (row.webauthn_credential_id or "").strip()
    ):
        raise WebAuthnError("aucun passkey enregistré")
    rp_id, _origin = rp_id_and_origin(settings)
    cred_id = base64url_to_bytes(row.webauthn_credential_id)
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=cred_id, type=PublicKeyCredentialType.PUBLIC_KEY
            )
        ],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return json.loads(options_to_json(options)), options.challenge


def verify_authentication(
    db: Session,
    settings: Settings,
    *,
    user_email: str,
    credential: dict[str, Any] | str,
    expected_challenge: bytes,
) -> AdminMfaCredential:
    row = _get_credential(db, user_email)
    if (
        row is None
        or not row.webauthn_enabled
        or not (row.webauthn_credential_id or "").strip()
        or not (row.webauthn_public_key or "").strip()
    ):
        raise WebAuthnError("passkey non configuré")
    rp_id, origin = rp_id_and_origin(settings)
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(row.webauthn_public_key),
            credential_current_sign_count=int(row.webauthn_sign_count or 0),
            require_user_verification=False,
        )
    except Exception as exc:
        logger.warning("webauthn assertion verify failed: %s", type(exc).__name__)
        raise WebAuthnError("assertion WebAuthn invalide") from exc

    row.webauthn_sign_count = int(verified.new_sign_count or row.webauthn_sign_count or 0)
    row.updated_at = utcnow()
    db.commit()
    db.refresh(row)
    return row


def disable_webauthn(db: Session, user_email: str) -> None:
    row = _get_credential(db, user_email)
    if row is None:
        return
    row.webauthn_enabled = False
    row.webauthn_credential_id = None
    row.webauthn_public_key = None
    row.webauthn_sign_count = 0
    row.webauthn_transports = None
    row.updated_at = utcnow()
    db.commit()
