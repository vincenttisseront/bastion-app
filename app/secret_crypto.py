"""Fernet encryption for realm OIDC client secrets."""

import base64
import hashlib
import secrets

from cryptography.fernet import Fernet, InvalidToken

from app.sso_settings import Settings


def _fernet(settings: Settings) -> Fernet:
    raw = settings.portal_secret_encryption_key
    if not raw:
        raise ValueError("PORTAL_SECRET_ENCRYPTION_KEY is not configured")
    try:
        return Fernet(raw.encode("ascii"))
    except (ValueError, TypeError):
        digest = hashlib.sha256(raw.encode("utf-8")).digest()
        return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(plaintext: str, settings: Settings) -> str:
    return _fernet(settings).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str, settings: Settings) -> str:
    try:
        return _fernet(settings).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Failed to decrypt secret") from exc


def generate_cookie_secret() -> str:
    return secrets.token_urlsafe(32)
