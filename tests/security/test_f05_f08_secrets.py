"""F-05 / F-08: dedicated secrets fail-closed — DB portal_settings, not .env."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from app.breakglass import resolve_breakglass_signing_secret_with_source
from app.runtime_secrets_service import (
    ensure_portal_runtime_secrets,
    reset_runtime_secrets_cache_for_tests,
    resolve_session_hop_secret,
)
from app.sso_settings import Settings, get_settings


def test_production_disables_legacy_jwt_fallback():
    settings = Settings(
        environment="production",
        breakglass_jwt_secret="",
        session_hop_secret="",
        vault_portal_internal_token="should-not-be-used-as-jwt",
        breakglass_jwt_secret_fallback_enabled=True,
        portal_secret_encryption_key=Fernet.generate_key().decode(),
        database_url="sqlite://",
    )
    assert settings.breakglass_jwt_secret_fallback_enabled is False
    assert settings.is_production


def test_production_uses_db_breakglass_not_vault_token(db_session):
    reset_runtime_secrets_cache_for_tests()
    key = Fernet.generate_key().decode()
    settings = Settings(
        environment="production",
        breakglass_jwt_secret="",
        session_hop_secret="",
        vault_portal_internal_token="vault-token-only",
        portal_secret_encryption_key=key,
        database_url="sqlite://",
    )
    ensure_portal_runtime_secrets(db_session, settings, actor="test")
    secret, source = resolve_breakglass_signing_secret_with_source(
        settings, db=db_session
    )
    assert source == "ui"
    assert secret != "vault-token-only"


def test_production_fails_without_db_breakglass(db_session):
    reset_runtime_secrets_cache_for_tests()
    settings = Settings(
        environment="production",
        breakglass_jwt_secret="",
        vault_portal_internal_token="vault-token-only",
        portal_secret_encryption_key=Fernet.generate_key().decode(),
        database_url="sqlite://",
    )
    with pytest.raises(RuntimeError, match="portal_settings"):
        resolve_breakglass_signing_secret_with_source(settings, db=db_session)


def test_validation_without_db_does_not_raise_in_production():
    """Cookie validation must not 500 when db is absent (login / error pages)."""
    reset_runtime_secrets_cache_for_tests()
    from app.breakglass import _validation_secrets, validate_breakglass_cookie

    settings = Settings(
        environment="production",
        breakglass_jwt_secret="",
        vault_portal_internal_token="vault-token-only",
        portal_secret_encryption_key=Fernet.generate_key().decode(),
        database_url="sqlite://",
    )
    assert _validation_secrets(settings, db=None) == []
    assert validate_breakglass_cookie("not.a.jwt", db=None, settings=settings) is False


def test_boot_cache_allows_validation_without_db(db_session):
    reset_runtime_secrets_cache_for_tests()
    key = Fernet.generate_key().decode()
    settings = Settings(
        environment="production",
        breakglass_jwt_secret="",
        session_hop_secret="",
        vault_portal_internal_token="vault-token-only",
        portal_secret_encryption_key=key,
        database_url="sqlite://",
    )
    ensure_portal_runtime_secrets(db_session, settings, actor="test")
    secret, source = resolve_breakglass_signing_secret_with_source(
        settings, db=None, strict=False
    )
    assert source == "ui"
    assert secret


def test_development_allows_missing_breakglass_with_warning_path():
    settings = Settings(
        environment="development",
        breakglass_jwt_secret="",
        session_hop_secret="dev-hop-secret",
        vault_portal_internal_token="legacy",
        portal_secret_encryption_key="k",
        database_url="sqlite://",
    )
    assert not settings.is_production
    assert settings.breakglass_jwt_secret_fallback_enabled is True


def test_hop_secret_no_dev_fallback(monkeypatch):
    from app.robotic import session_cookie_hop as hop
    from app.runtime_secrets_service import reset_runtime_secrets_cache_for_tests

    reset_runtime_secrets_cache_for_tests()
    settings = Settings(
        environment="test",
        session_hop_secret="",
        portal_secret_encryption_key="k",
        database_url="sqlite://",
    )
    with pytest.raises(RuntimeError, match="session hop secret missing"):
        hop._hop_secret(settings)


def test_lifespan_ensures_hop_from_db_outside_test(db_session, monkeypatch):
    """Non-test boot ensures hop secret into portal_settings (not .env)."""
    monkeypatch.setenv("PORTAL_ENVIRONMENT", "development")
    monkeypatch.delenv("SESSION_HOP_SECRET", raising=False)
    monkeypatch.setenv(
        "PORTAL_SECRET_ENCRYPTION_KEY", Fernet.generate_key().decode()
    )
    get_settings.cache_clear()
    reset_runtime_secrets_cache_for_tests()
    settings = get_settings()
    assert not settings.is_test
    assert not (settings.session_hop_secret or "").strip()
    ensure_portal_runtime_secrets(db_session, settings, actor="boot")
    hop = resolve_session_hop_secret(settings, db=db_session)
    assert hop
    get_settings.cache_clear()
    reset_runtime_secrets_cache_for_tests()
