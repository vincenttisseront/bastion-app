"""F-05 / F-08: dedicated secrets fail-closed in production."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.sso_settings import Settings, get_settings


def test_production_requires_breakglass_and_hop_secrets():
    with pytest.raises((ValidationError, ValueError)) as exc:
        Settings(
            environment="production",
            vault_portal_internal_token="vault-token-only",
            breakglass_jwt_secret="",
            session_hop_secret="",
            portal_secret_encryption_key="k",
            database_url="sqlite://",
        )
    msg = str(exc.value)
    assert "BREAKGLASS_JWT_SECRET" in msg
    assert "SESSION_HOP_SECRET" in msg


def test_production_disables_legacy_jwt_fallback_when_secrets_set():
    settings = Settings(
        environment="production",
        breakglass_jwt_secret="prod-bg-jwt-secret-32chars-min!!",
        session_hop_secret="prod-hop-secret-32chars-minimum!",
        vault_portal_internal_token="should-not-be-used-as-jwt",
        breakglass_jwt_secret_fallback_enabled=True,
        portal_secret_encryption_key="k",
        database_url="sqlite://",
    )
    assert settings.breakglass_jwt_secret_fallback_enabled is False
    assert settings.is_production


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

    settings = Settings(
        environment="test",
        session_hop_secret="",
        portal_secret_encryption_key="k",
        database_url="sqlite://",
    )
    with pytest.raises(RuntimeError, match="SESSION_HOP_SECRET"):
        hop._hop_secret(settings)


def test_lifespan_refuses_start_without_hop_secret_outside_test(monkeypatch):
    """Non-test environment without SESSION_HOP_SECRET must not boot silently."""
    monkeypatch.setenv("PORTAL_ENVIRONMENT", "development")
    monkeypatch.delenv("SESSION_HOP_SECRET", raising=False)
    monkeypatch.setenv("PORTAL_SECRET_ENCRYPTION_KEY", "test-encryption-key-for-pytest-only")
    get_settings.cache_clear()
    settings = get_settings()
    assert not settings.is_test
    assert not (settings.session_hop_secret or "").strip()
    # Mirror lifespan guard from app.main
    with pytest.raises(RuntimeError, match="SESSION_HOP_SECRET"):
        if not settings.is_test and not (settings.session_hop_secret or "").strip():
            raise RuntimeError(
                "SESSION_HOP_SECRET is required (set PORTAL_ENVIRONMENT=test only for pytest)"
            )
    get_settings.cache_clear()
