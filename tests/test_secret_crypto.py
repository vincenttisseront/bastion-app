"""Secret encryption key resolution."""

from types import SimpleNamespace

import pytest

from app.secret_crypto import (
    decrypt_secret,
    encrypt_secret,
    encryption_configured,
)


def test_encryption_uses_portal_secret_key():
    settings = SimpleNamespace(
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        vault_portal_vault_fernet_key="",
    )
    assert encryption_configured(settings)
    cipher = encrypt_secret("my-secret", settings)
    assert decrypt_secret(cipher, settings) == "my-secret"


def test_encryption_falls_back_to_vault_fernet_key():
    settings = SimpleNamespace(
        portal_secret_encryption_key="",
        vault_portal_vault_fernet_key="fallback-fernet-key-for-pytest",
    )
    assert encryption_configured(settings)
    cipher = encrypt_secret("oidc-secret", settings)
    assert decrypt_secret(cipher, settings) == "oidc-secret"


def test_encryption_missing_both_keys():
    from app.vault.encryption_key_store import reset_active_cache_for_tests

    reset_active_cache_for_tests()
    settings = SimpleNamespace(portal_secret_encryption_key="", vault_portal_vault_fernet_key="")
    assert not encryption_configured(settings)
    with pytest.raises(ValueError, match="PORTAL_SECRET_ENCRYPTION_KEY|Aucune clé Fernet"):
        encrypt_secret("x", settings)
