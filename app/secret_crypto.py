"""Fernet encryption for portal vault secrets (app credentials + realm OIDC)."""

from __future__ import annotations

import base64
import hashlib
import secrets

from cryptography.fernet import Fernet, InvalidToken

from app.sso_settings import Settings

ENCRYPTION_KEY_ENV = "PORTAL_SECRET_ENCRYPTION_KEY"


def _env_key_material(settings: Settings) -> str:
    """Legacy env delivery (Phase A) — primary then vault fallback."""
    raw = (settings.portal_secret_encryption_key or "").strip()
    if not raw:
        raw = (settings.vault_portal_vault_fernet_key or "").strip()
    return raw


def _encryption_key_material(settings: Settings) -> str:
    """
    Active key from local store when initialized; else legacy env fallback
    (tests / pre-ensure boot path).
    """
    try:
        from app.vault.encryption_key_store import try_get_active_key

        material = try_get_active_key()
        if material:
            return material
    except Exception:
        pass
    raw = _env_key_material(settings)
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
        "Aucune clé Fernet disponible (store local VAULT_KEYS_DIR ni "
        f"{ENCRYPTION_KEY_ENV}/VAULT_PORTAL_VAULT_FERNET_KEY). "
        "Vérifiez le répertoire de clés ou la migration depuis l'env."
    )


def fernet_from_key_material(raw: str) -> Fernet:
    """Build a Fernet instance from key material (url-safe Fernet key or passphrase)."""
    material = (raw or "").strip()
    if not material:
        raise ValueError(encryption_config_error())
    try:
        return Fernet(material.encode("ascii"))
    except (ValueError, TypeError):
        digest = hashlib.sha256(material.encode("utf-8")).digest()
        return Fernet(base64.urlsafe_b64encode(digest))


def _fernet(settings: Settings) -> Fernet:
    return fernet_from_key_material(_encryption_key_material(settings))


def get_fernet(settings: Settings) -> Fernet:
    """Public Fernet instance for the active vault key (blobs, secrets)."""
    return _fernet(settings)


def encrypt_secret(plaintext: str, settings: Settings) -> str:
    return _fernet(settings).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str, settings: Settings) -> str:
    try:
        return _fernet(settings).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Failed to decrypt secret") from exc


def encrypt_with_key(plaintext: str, key_material: str) -> str:
    return fernet_from_key_material(key_material).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_with_key(ciphertext: str, key_material: str) -> str:
    try:
        return (
            fernet_from_key_material(key_material)
            .decrypt(ciphertext.encode("ascii"))
            .decode("utf-8")
        )
    except InvalidToken as exc:
        raise ValueError("Failed to decrypt secret") from exc


def generate_cookie_secret() -> str:
    return secrets.token_urlsafe(32)
