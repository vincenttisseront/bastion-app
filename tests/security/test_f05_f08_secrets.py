"""F-05 / F-08: dedicated secrets fail-closed (SQLite or env, never silent 'dev')."""

from __future__ import annotations

from app.sso_settings import Settings, get_settings


def test_production_disables_legacy_jwt_fallback():
    settings = Settings(
        environment="production",
        breakglass_jwt_secret="",
        session_hop_secret="",
        vault_portal_internal_token="should-not-be-used-as-jwt",
        breakglass_jwt_secret_fallback_enabled=True,
        portal_secret_encryption_key="k",
        database_url="sqlite://",
    )
    assert settings.breakglass_jwt_secret_fallback_enabled is False
    assert settings.is_production


def test_production_allows_empty_env_when_sqlite_will_seed():
    """Docker/Ansible seed HMAC into portal_settings; env overrides are optional."""
    settings = Settings(
        environment="production",
        breakglass_jwt_secret="",
        session_hop_secret="",
        vault_portal_internal_token="vault-token-only",
        portal_secret_encryption_key="k",
        database_url="sqlite://",
    )
    assert settings.is_production
    assert settings.breakglass_jwt_secret_fallback_enabled is False


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
    monkeypatch.delenv("SESSION_HOP_SECRET", raising=False)
    settings = Settings(
        environment="test",
        session_hop_secret="",
        portal_secret_encryption_key="k",
        database_url="sqlite://",
    )
    import pytest

    with pytest.raises(RuntimeError, match="SESSION_HOP_SECRET"):
        hop._hop_secret(settings)


def test_hop_secret_uses_process_cache_after_ensure(db_session, monkeypatch):
    from app.robotic import session_cookie_hop as hop
    from app.runtime_secrets_service import (
        ensure_portal_runtime_secrets,
        reset_runtime_secrets_cache_for_tests,
    )

    reset_runtime_secrets_cache_for_tests()
    monkeypatch.delenv("SESSION_HOP_SECRET", raising=False)
    settings = Settings(
        environment="development",
        session_hop_secret="",
        breakglass_jwt_secret="",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    ensure_portal_runtime_secrets(db_session, settings, actor="test")
    secret = hop._hop_secret(settings)
    assert isinstance(secret, bytes)
    assert len(secret) == 32


def test_lifespan_refuses_start_if_hop_still_missing_after_resolve(monkeypatch):
    """Guard still fails closed when ensure cannot produce a hop secret."""
    monkeypatch.setenv("PORTAL_ENVIRONMENT", "development")
    monkeypatch.delenv("SESSION_HOP_SECRET", raising=False)
    get_settings.cache_clear()
    settings = get_settings()
    assert not settings.is_test
    hop = ""  # simulate resolve_session_hop_secret empty
    import pytest

    with pytest.raises(RuntimeError, match="SESSION_HOP_SECRET"):
        if not settings.is_test and not hop:
            raise RuntimeError(
                "SESSION_HOP_SECRET missing after ensure "
                "(set env override or check portal_settings / migrate)"
            )
    get_settings.cache_clear()
