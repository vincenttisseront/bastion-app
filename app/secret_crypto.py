"""Fernet encryption for realm OIDC client secrets."""

import base64
import hashlib
import secrets

from cryptography.fernet import Fernet, InvalidToken

from app.sso_settings import Settings

ENCRYPTION_KEY_ENV = "PORTAL_SECRET_ENCRYPTION_KEY"


def _encryption_key_material(settings: Settings) -> str:
    """Primary: PORTAL_SECRET_ENCRYPTION_KEY; fallback: VAULT_PORTAL_VAULT_FERNET_KEY."""
    raw = (settings.portal_secret_encryption_key or "").strip()
    if not raw:
        raw = (settings.vault_portal_vault_fernet_key or "").strip()
    if not raw:
        raise ValueError(encryption_config_error())
    return raw


def encryption_configured(settings: Settings) -> bool:
    try:
        _encryption_key_material(settings)
        return True
    except ValueError:
        return False


def encryption_config_error() -> str:
    return (
        f"{ENCRYPTION_KEY_ENV} (ou VAULT_PORTAL_VAULT_FERNET_KEY) n'est pas configurée. "
        "Ajoutez une clé Fernet dans /opt/sso-portal/.env puis redémarrez sso-portal."
    )


def _fernet(settings: Settings) -> Fernet:
    raw = _encryption_key_material(settings)
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
