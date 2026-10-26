"""Admin TOTP enrollment / verification (pyotp + portal Fernet)."""

from __future__ import annotations

import base64
import io
import logging
from typing import Any

import pyotp
import qrcode
from sqlalchemy.orm import Session

from app.models import AdminMfaCredential, utcnow
from app.secret_crypto import decrypt_secret, encrypt_secret, encryption_configured
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

TOTP_ISSUER = "Bastion Portal"
VALID_WINDOW = 1  # ±30s


def _norm_email(email: str) -> str:
    return (email or "").strip().lower()


def get_or_create_credential(db: Session, user_email: str) -> AdminMfaCredential:
    email = _norm_email(user_email)
    row = (
        db.query(AdminMfaCredential)
        .filter(AdminMfaCredential.user_email == email)
        .first()
    )
    if row is not None:
        return row
    row = AdminMfaCredential(
        user_email=email,
        totp_enabled=False,
        webauthn_enabled=False,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def totp_enabled_for(db: Session, user_email: str) -> bool:
    email = _norm_email(user_email)
    if not email:
        return False
    row = (
        db.query(AdminMfaCredential)
        .filter(AdminMfaCredential.user_email == email)
        .first()
    )
    return bool(row and row.totp_enabled and (row.totp_secret or "").strip())


def generate_new_totp_setup(
    db: Session, settings: Settings, user_email: str
) -> dict[str, Any]:
    """Create/replace pending TOTP secret (encrypted); return QR + display secret.

    Does **not** enable TOTP until ``confirm_totp_enrollment`` succeeds.
    """
    if not encryption_configured(settings):
        raise ValueError(
            "Chiffrement Fernet non configuré — impossible de stocker le secret TOTP"
        )
    email = _norm_email(user_email)
    raw_secret = pyotp.random_base32()
    encrypted = encrypt_secret(raw_secret, settings)
    totp = pyotp.TOTP(raw_secret)
    provisioning_url = totp.provisioning_uri(name=email, issuer_name=TOTP_ISSUER)
    qr_data_url = _qr_data_url(provisioning_url)

    row = get_or_create_credential(db, email)
    row.totp_secret = encrypted
    row.totp_enabled = False
    row.updated_at = utcnow()
    db.commit()
    db.refresh(row)
    return {
        "secret_display": raw_secret,
        "provisioning_url": provisioning_url,
        "qr_data_url": qr_data_url,
        "totp_enabled": False,
    }


def verify_totp_token(
    settings: Settings, encrypted_secret: str, token: str
) -> bool:
    code = (token or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    try:
        raw = decrypt_secret(encrypted_secret, settings)
    except Exception:
        logger.warning("totp: failed to decrypt secret")
        return False
    try:
        return bool(pyotp.TOTP(raw).verify(code, valid_window=VALID_WINDOW))
    except Exception:
        return False


def confirm_totp_enrollment(
    db: Session,
    settings: Settings,
    user_email: str,
    token: str,
) -> bool:
    """Validate first code and set ``totp_enabled=True``."""
    row = get_or_create_credential(db, user_email)
    if not (row.totp_secret or "").strip():
        return False
    if not verify_totp_token(settings, row.totp_secret, token):
        return False
    row.totp_enabled = True
    row.updated_at = utcnow()
    db.commit()
    return True


def disable_totp(
    db: Session,
    settings: Settings,
    user_email: str,
    token: str,
) -> bool:
    """Disable TOTP after verifying a current code (anti-lockout self-service)."""
    row = get_or_create_credential(db, user_email)
    if not row.totp_enabled or not (row.totp_secret or "").strip():
        row.totp_secret = None
        row.totp_enabled = False
        row.updated_at = utcnow()
        db.commit()
        return True
    if not verify_totp_token(settings, row.totp_secret, token):
        return False
    row.totp_secret = None
    row.totp_enabled = False
    row.updated_at = utcnow()
    db.commit()
    return True


def verify_login_totp(
    db: Session, settings: Settings, user_email: str, token: str
) -> bool:
    row = get_or_create_credential(db, user_email)
    if not row.totp_enabled or not (row.totp_secret or "").strip():
        return False
    return verify_totp_token(settings, row.totp_secret, token)


def mfa_status_dict(db: Session, user_email: str) -> dict[str, Any]:
    row = (
        db.query(AdminMfaCredential)
        .filter(AdminMfaCredential.user_email == _norm_email(user_email))
        .first()
    )
    if row is None:
        return {
            "totp_enabled": False,
            "totp_pending": False,
            "webauthn_enabled": False,
        }
    return {
        "totp_enabled": bool(row.totp_enabled),
        "totp_pending": bool(
            (row.totp_secret or "").strip() and not row.totp_enabled
        ),
        "webauthn_enabled": bool(row.webauthn_enabled),
    }


def _qr_data_url(payload: str) -> str:
    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"
