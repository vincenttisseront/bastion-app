"""Fernet encryption for portal vault secrets (app credentials + realm OIDC)."""

from __future__ import annotations

import secrets

from cryptography.fernet import Fernet, InvalidToken

from app.sso_settings import Settings
from app.vault.encryption_key_store import (
    as_fernet_key,
    env_key_material,
    try_get_active_key,
)

ENCRYPTION_KEY_ENV = "PORTAL_SECRET_ENCRYPTION_KEY"


def encryption_config_error() -> str:
    return (
        "Aucune clé Fernet disponible (store local VAULT_KEYS_DIR ni "
        f"{ENCRYPTION_KEY_ENV}/VAULT_PORTAL_VAULT_FERNET_KEY). "
        "Vérifiez le répertoire de clés ou la migration depuis l'env."
    )


def fernet_from_key_material(raw: str, *, allow_passphrase: bool = False) -> Fernet:
    """Fernet for ``raw``. Passphrases are only accepted from legacy/operator inputs."""
    material = (raw or "").strip()
    if not material:
        raise ValueError(encryption_config_error())
    if allow_passphrase:
        material = as_fernet_key(material)
    try:
        return Fernet(material.encode("ascii"))
    except (ValueError, TypeError):
        raise ValueError(
            "Clé Fernet invalide (44 caractères base64 url-safe attendus)"
        ) from None


def get_fernet(settings: Settings) -> Fernet:
    """Fernet for the active vault key; legacy env fallback before the store is initialised."""
    active = try_get_active_key()
    if active:
        return fernet_from_key_material(active)
    env = env_key_material(settings)
    if not env:
        raise ValueError(encryption_config_error())
    return fernet_from_key_material(env, allow_passphrase=True)


def encryption_configured(settings: Settings) -> bool:
    return bool(try_get_active_key() or env_key_material(settings))


def _encrypt(fernet: Fernet, plaintext: str) -> str:
    return fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")


def _decrypt(fernet: Fernet, ciphertext: str) -> str:
    try:
        return fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Failed to decrypt secret") from exc


def encrypt_secret(plaintext: str, settings: Settings) -> str:
    return _encrypt(get_fernet(settings), plaintext)


def decrypt_secret(ciphertext: str, settings: Settings) -> str:
    return _decrypt(get_fernet(settings), ciphertext)


def encrypt_with_key(plaintext: str, key_material: str) -> str:
    """Encrypt with explicit key material (rotation; operators may still hold a passphrase)."""
    return _encrypt(fernet_from_key_material(key_material, allow_passphrase=True), plaintext)


def decrypt_with_key(ciphertext: str, key_material: str) -> str:
    return _decrypt(fernet_from_key_material(key_material, allow_passphrase=True), ciphertext)


def generate_cookie_secret() -> str:
    return secrets.token_urlsafe(32)
