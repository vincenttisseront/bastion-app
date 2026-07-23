"""Break-glass JWT secret status + UI remediation (env / UI / legacy)."""

from __future__ import annotations

from app.breakglass import (
    create_breakglass_token,
    decode_breakglass_token_with_fallback,
    resolve_breakglass_signing_secret,
    resolve_breakglass_signing_secret_with_source,
    validate_breakglass_cookie,
)
from app.breakglass_secret_service import (
    build_breakglass_secret_status,
    generate_or_rotate_ui_breakglass_secret,
    get_ui_breakglass_previous_secret,
    get_ui_breakglass_secret,
)
from app.sso_settings import Settings

LEGACY = "legacy-vault-portal-internal-token"
ENV_SECRET = "dedicated-bg-jwt-secret-from-env"
ENC_KEY = "test-encryption-key-for-pytest-only"


def _settings(**kwargs) -> Settings:
    base = dict(
        vault_portal_internal_token=LEGACY,
        breakglass_jwt_secret="",
        breakglass_jwt_secret_fallback_enabled=True,
        portal_secret_encryption_key=ENC_KEY,
        database_url="sqlite://",
    )
    base.update(kwargs)
    return Settings(**base)


def test_breakglass_secret_status_non_conforming_when_legacy_only(db_session):
    settings = _settings()
    secret, source = resolve_breakglass_signing_secret_with_source(
        settings, db=db_session
    )
    assert source == "legacy"
    assert secret == LEGACY
    status = build_breakglass_secret_status(
        settings, db_session, effective_secret=secret, effective_source=source
    )
    assert status.conforming is False
    assert status.env_defined is False
    assert status.ui_secret_active is False
    assert status.can_generate is True
    assert status.effective_distinct_from_vault_token is False
    public = status.to_public_dict()
    assert LEGACY not in str(public.values())
    assert all(
        k
        in (
            "env_defined",
            "ui_secret_present",
            "ui_secret_active",
            "effective_source",
            "effective_distinct_from_vault_token",
            "legacy_fallback_enabled",
            "conforming",
            "can_generate",
            "can_rotate",
        )
        for k in public
    )


def test_breakglass_secret_status_generate_makes_conforming(db_session):
    settings = _settings()
    before_token = create_breakglass_token("admin", LEGACY)
    assert validate_breakglass_cookie(before_token, settings=settings, db=db_session)

    status = generate_or_rotate_ui_breakglass_secret(
        db_session, settings, actor="admin@test"
    )
    assert status.conforming is True
    assert status.ui_secret_active is True
    assert status.can_generate is False
    assert status.can_rotate is True
    assert status.effective_source == "ui"

    ui = get_ui_breakglass_secret(db_session, settings)
    assert ui and ui != LEGACY
    assert resolve_breakglass_signing_secret(settings, db=db_session) == ui

    new_token = create_breakglass_token("admin", ui)
    assert validate_breakglass_cookie(new_token, settings=settings, db=db_session)
    # Cookie signed just before generation still valid (legacy fallback / transition).
    assert validate_breakglass_cookie(before_token, settings=settings, db=db_session)
    payload, used_legacy = decode_breakglass_token_with_fallback(
        before_token, settings, db=db_session
    )
    assert payload is not None
    assert used_legacy is True


def test_breakglass_secret_status_button_blocked_when_env_defined(db_session):
    settings = _settings(breakglass_jwt_secret=ENV_SECRET)
    secret, source = resolve_breakglass_signing_secret_with_source(
        settings, db=db_session
    )
    assert source == "env"
    status = build_breakglass_secret_status(
        settings, db_session, effective_secret=secret, effective_source=source
    )
    assert status.env_defined is True
    assert status.can_generate is False
    assert status.can_rotate is False
    assert status.conforming is True

    try:
        generate_or_rotate_ui_breakglass_secret(
            db_session, settings, actor="admin@test"
        )
        assert False, "expected PermissionError"
    except PermissionError:
        pass
    assert get_ui_breakglass_secret(db_session, settings) is None


def test_breakglass_secret_status_ui_rotation_keeps_old_cookie_valid(db_session):
    settings = _settings()
    generate_or_rotate_ui_breakglass_secret(db_session, settings, actor="admin@test")
    first = get_ui_breakglass_secret(db_session, settings)
    assert first
    old_cookie = create_breakglass_token("admin", first)

    generate_or_rotate_ui_breakglass_secret(db_session, settings, actor="admin@test")
    second = get_ui_breakglass_secret(db_session, settings)
    previous = get_ui_breakglass_previous_secret(db_session, settings)
    assert second and second != first
    assert previous == first
    assert resolve_breakglass_signing_secret(settings, db=db_session) == second
    assert validate_breakglass_cookie(old_cookie, settings=settings, db=db_session)
    payload, used_legacy = decode_breakglass_token_with_fallback(
        old_cookie, settings, db=db_session
    )
    assert payload is not None
    assert used_legacy is False


def test_breakglass_secret_status_resolution_prefers_env_over_ui(db_session):
    settings_ui = _settings()
    generate_or_rotate_ui_breakglass_secret(db_session, settings_ui, actor="admin@test")
    ui = get_ui_breakglass_secret(db_session, settings_ui)
    assert ui

    settings_env = _settings(breakglass_jwt_secret=ENV_SECRET)
    secret, source = resolve_breakglass_signing_secret_with_source(
        settings_env, db=db_session
    )
    assert source == "env"
    assert secret == ENV_SECRET
    assert secret != ui


def test_breakglass_secret_status_api_dict_never_leaks_secrets(db_session):
    settings = _settings(breakglass_jwt_secret=ENV_SECRET)
    secret, source = resolve_breakglass_signing_secret_with_source(
        settings, db=db_session
    )
    status = build_breakglass_secret_status(
        settings, db_session, effective_secret=secret, effective_source=source
    )
    blob = str(status.to_public_dict())
    assert ENV_SECRET not in blob
    assert LEGACY not in blob
