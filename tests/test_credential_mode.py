"""credential_mode shared vs individual_required — resolution rules."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.models import App
from app.sso_settings import Settings
from app.vault.app_credential_service import set_app_credential
from app.vault.user_app_credential_service import (
    get_effective_credential,
    needs_individual_credential_setup,
    resolve_credential,
    set_user_credential,
)

SECRET_SHARED = "SharedModeSecret-MustNotLeak"
SECRET_USER = "UserModeSecret-MustNotLeak"
KC_USER = "e189ed16-79f0-4fa1-85ee-1bb7ff28052c"


def _settings(**kwargs) -> Settings:
    defaults = {
        "vault_portal_internal_token": "test-secret",
        "portal_secret_encryption_key": "test-encryption-key-for-pytest-only",
        "database_url": "sqlite://",
    }
    defaults.update(kwargs)
    return Settings(**defaults)


def _make_app(
    db: Session,
    slug: str = "transfer",
    *,
    credential_mode: str = "shared",
) -> App:
    app = App(
        slug=slug,
        label="Transfer",
        upstream_url="https://crush.example/",
        robotic_driver="crushftp",
        access_mode="legacy_path_proxy",
        credential_mode=credential_mode,
        enabled=True,
    )
    db.add(app)
    db.commit()
    return app


def test_individual_required_without_override_returns_none_even_with_shared(
    db_session: Session,
):
    app = _make_app(db_session, credential_mode="individual_required")
    settings = _settings()
    set_app_credential(db_session, "transfer", "shared-robot", SECRET_SHARED, settings)

    row, source = get_effective_credential(db_session, "transfer", KC_USER)
    assert row is None
    assert source is None
    assert needs_individual_credential_setup(db_session, app, KC_USER) is True

    with pytest.raises(Exception, match="credential"):
        resolve_credential(db_session, "transfer", settings, KC_USER)


def test_individual_required_with_override_returns_override(db_session: Session):
    app = _make_app(db_session, credential_mode="individual_required")
    settings = _settings()
    set_app_credential(db_session, "transfer", "shared-robot", SECRET_SHARED, settings)
    set_user_credential(
        db_session, "transfer", KC_USER, "user-robot", SECRET_USER, settings
    )

    row, source = get_effective_credential(db_session, "transfer", KC_USER)
    assert source == "user_override"
    assert row is not None
    assert row.robotic_username == "user-robot"
    assert needs_individual_credential_setup(db_session, app, KC_USER) is False

    resolved, password = resolve_credential(db_session, "transfer", settings, KC_USER)
    assert resolved.source == "user_override"
    assert password == SECRET_USER
    assert SECRET_SHARED not in password


def test_shared_mode_unchanged_fallback(db_session: Session):
    app = _make_app(db_session, credential_mode="shared")
    settings = _settings()
    set_app_credential(db_session, "transfer", "shared-robot", SECRET_SHARED, settings)

    row, source = get_effective_credential(db_session, "transfer", KC_USER)
    assert source == "shared"
    assert row is not None
    assert row.robotic_username == "shared-robot"
    assert needs_individual_credential_setup(db_session, app, KC_USER) is False

    resolved, password = resolve_credential(db_session, "transfer", settings, KC_USER)
    assert resolved.source == "shared"
    assert password == SECRET_SHARED


def test_default_credential_mode_is_shared(db_session: Session):
    app = App(
        slug="other",
        label="Other",
        upstream_url="https://example/",
        robotic_driver="crushftp",
        enabled=True,
    )
    db_session.add(app)
    db_session.commit()
    db_session.refresh(app)
    assert (app.credential_mode or "shared") == "shared"
