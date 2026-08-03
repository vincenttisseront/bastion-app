"""Runtime HMAC secrets live in portal_settings (not .env)."""

from __future__ import annotations

from cryptography.fernet import Fernet

from app.breakglass import resolve_breakglass_signing_secret_with_source
from app.oidc_bff_config_service import resolve_oidc_session_jwt_secret
from app.runtime_secrets_service import (
    ensure_portal_runtime_secrets,
    reset_runtime_secrets_cache_for_tests,
    resolve_session_hop_secret,
)
from app.sso_settings import Settings


def test_ensure_creates_hop_and_breakglass_in_db(db_session, monkeypatch):
    monkeypatch.delenv("SESSION_HOP_SECRET", raising=False)
    monkeypatch.delenv("BREAKGLASS_JWT_SECRET", raising=False)
    monkeypatch.delenv("OIDC_SESSION_JWT_SECRET", raising=False)
    reset_runtime_secrets_cache_for_tests()
    key = Fernet.generate_key().decode()
    settings = Settings(
        environment="production",
        session_hop_secret="",
        breakglass_jwt_secret="",
        oidc_session_jwt_secret="",
        vault_portal_internal_token="vault-token",
        portal_secret_encryption_key=key,
        database_url="sqlite://",
    )

    result = ensure_portal_runtime_secrets(db_session, settings, actor="test")
    assert "session_hop" in result["created"]
    assert "breakglass_jwt" in result["created"]
    assert "oidc_session_jwt" in result["created"]

    hop = resolve_session_hop_secret(settings, db=db_session)
    assert hop
    assert hop != "vault-token"

    oidc = resolve_oidc_session_jwt_secret(db_session, settings)
    assert oidc
    assert oidc != "vault-token"
    assert oidc != hop

    secret, source = resolve_breakglass_signing_secret_with_source(
        settings, db=db_session
    )
    assert source == "ui"
    assert secret
    assert secret != "vault-token"

    result2 = ensure_portal_runtime_secrets(db_session, settings, actor="test")
    assert result2["created"] == []
    assert resolve_session_hop_secret(settings, db=db_session) == hop
    assert resolve_oidc_session_jwt_secret(db_session, settings) == oidc


def test_oidc_session_jwt_survives_process_restart(db_session, monkeypatch):
    """Rebuild simulation: new Settings without env must reuse DB HMAC."""
    monkeypatch.delenv("OIDC_SESSION_JWT_SECRET", raising=False)
    reset_runtime_secrets_cache_for_tests()
    key = Fernet.generate_key().decode()
    settings1 = Settings(
        environment="production",
        oidc_session_jwt_secret="",
        session_hop_secret="",
        breakglass_jwt_secret="",
        vault_portal_internal_token="vault-token",
        portal_secret_encryption_key=key,
        database_url="sqlite://",
    )
    ensure_portal_runtime_secrets(db_session, settings1, actor="test")
    first = resolve_oidc_session_jwt_secret(db_session, settings1)
    assert first

    reset_runtime_secrets_cache_for_tests()
    settings2 = Settings(
        environment="production",
        oidc_session_jwt_secret="",
        session_hop_secret="",
        breakglass_jwt_secret="",
        vault_portal_internal_token="vault-token",
        portal_secret_encryption_key=key,
        database_url="sqlite://",
    )
    # Boot ensure on "new" process — must not rotate the secret.
    ensure_portal_runtime_secrets(db_session, settings2, actor="test")
    second = resolve_oidc_session_jwt_secret(db_session, settings2)
    assert second == first


def test_production_settings_no_longer_require_env_hmac():
    settings = Settings(
        environment="production",
        breakglass_jwt_secret="",
        session_hop_secret="",
        oidc_session_jwt_secret="",
        vault_portal_internal_token="vault-token-only",
        portal_secret_encryption_key=Fernet.generate_key().decode(),
        database_url="sqlite://",
    )
    assert settings.is_production
    assert settings.breakglass_jwt_secret_fallback_enabled is False
    assert settings.oidc_session_jwt_secret == ""


def test_env_hop_overrides_db(db_session):
    reset_runtime_secrets_cache_for_tests()
    key = Fernet.generate_key().decode()
    settings = Settings(
        environment="development",
        session_hop_secret="env-hop-override-for-pytest",
        portal_secret_encryption_key=key,
        database_url="sqlite://",
    )
    ensure_portal_runtime_secrets(db_session, settings, actor="test")
    assert resolve_session_hop_secret(settings, db=db_session) == (
        "env-hop-override-for-pytest"
    )
