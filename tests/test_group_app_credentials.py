"""Group-scoped vault credentials — shared account + exclusions + priority."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.models import App, RBACGroup
from app.sso_settings import Settings
from app.vault.app_credential_service import set_app_credential
from app.vault.group_app_credential_service import (
    add_group_credential_exclusion,
    set_group_credential,
)
from app.vault.user_app_credential_service import (
    GroupCredentialExcludedError,
    get_effective_credential,
    needs_individual_credential_setup,
    resolve_credential,
    set_user_credential,
)

SECRET_SHARED = "AppWideShared-Secret"
SECRET_GROUP = "GroupShared-Secret"
SECRET_GROUP_B = "GroupB-Shared-Secret"
SECRET_USER = "UserIndividual-Secret"
KC_USER = "kc-user-sdis-1"
KC_USER_EXCL = "kc-user-sdis-3"
GROUP_NAME = "SDIS 81"


def _settings(**kwargs) -> Settings:
    defaults = {
        "vault_portal_internal_token": "test-secret",
        "portal_secret_encryption_key": "test-encryption-key-for-pytest-only",
        "database_url": "sqlite://",
    }
    defaults.update(kwargs)
    return Settings(**defaults)


def _make_app(db: Session, slug: str = "transfer") -> App:
    app = App(
        slug=slug,
        label="Transfer",
        upstream_url="https://crush.example/",
        robotic_driver="crushftp",
        access_mode="legacy_path_proxy",
        enabled=True,
        credential_mode="shared",
    )
    db.add(app)
    db.commit()
    return app


def _make_group(db: Session, name: str = GROUP_NAME) -> RBACGroup:
    group = RBACGroup(name=name, keycloak_group_id=f"kc-g-{name}", path=f"/{name}")
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


def test_group_shared_used_before_app_shared(db_session: Session):
    _make_app(db_session)
    group = _make_group(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "app-robot", SECRET_SHARED, settings)
    set_group_credential(
        db_session,
        rbac_group_id=group.id,
        app_slug="transfer",
        robotic_username="sdis81-generic",
        plain_password=SECRET_GROUP,
        settings=settings,
        priority=100,
    )

    row, source = get_effective_credential(
        db_session, "transfer", KC_USER, group_names=[GROUP_NAME]
    )
    assert source == "group_shared"
    assert row is not None
    assert row.robotic_username == "sdis81-generic"

    resolved, password = resolve_credential(
        db_session, "transfer", settings, KC_USER, group_names=[GROUP_NAME]
    )
    assert resolved.source == "group_shared"
    assert password == SECRET_GROUP


def test_user_override_beats_group_shared(db_session: Session):
    _make_app(db_session)
    group = _make_group(db_session)
    settings = _settings()
    set_group_credential(
        db_session,
        rbac_group_id=group.id,
        app_slug="transfer",
        robotic_username="sdis81-generic",
        plain_password=SECRET_GROUP,
        settings=settings,
    )
    set_user_credential(
        db_session,
        "transfer",
        KC_USER_EXCL,
        "individual-robot",
        SECRET_USER,
        settings,
    )

    row, source = get_effective_credential(
        db_session, "transfer", KC_USER_EXCL, group_names=[GROUP_NAME]
    )
    assert source == "user_override"
    assert row.robotic_username == "individual-robot"


def test_exclusion_blocks_without_individual(db_session: Session):
    _make_app(db_session)
    group = _make_group(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "app-robot", SECRET_SHARED, settings)
    cred = set_group_credential(
        db_session,
        rbac_group_id=group.id,
        app_slug="transfer",
        robotic_username="sdis81-generic",
        plain_password=SECRET_GROUP,
        settings=settings,
    )
    add_group_credential_exclusion(db_session, cred.id, KC_USER_EXCL)

    row, source = get_effective_credential(
        db_session, "transfer", KC_USER_EXCL, group_names=[GROUP_NAME]
    )
    assert row is None
    assert source == "group_excluded"

    with pytest.raises(GroupCredentialExcludedError):
        resolve_credential(
            db_session, "transfer", settings, KC_USER_EXCL, group_names=[GROUP_NAME]
        )


def test_exclusion_with_individual_ok(db_session: Session):
    _make_app(db_session)
    group = _make_group(db_session)
    settings = _settings()
    cred = set_group_credential(
        db_session,
        rbac_group_id=group.id,
        app_slug="transfer",
        robotic_username="sdis81-generic",
        plain_password=SECRET_GROUP,
        settings=settings,
    )
    add_group_credential_exclusion(db_session, cred.id, KC_USER_EXCL)
    set_user_credential(
        db_session,
        "transfer",
        KC_USER_EXCL,
        "individual-robot",
        SECRET_USER,
        settings,
    )

    resolved, password = resolve_credential(
        db_session, "transfer", settings, KC_USER_EXCL, group_names=[GROUP_NAME]
    )
    assert resolved.source == "user_override"
    assert password == SECRET_USER


def test_explicit_priority_picks_higher_group(db_session: Session):
    _make_app(db_session)
    g_low = _make_group(db_session, "Clients")
    g_high = _make_group(db_session, "SDIS 81")
    settings = _settings()
    set_group_credential(
        db_session,
        rbac_group_id=g_low.id,
        app_slug="transfer",
        robotic_username="clients-generic",
        plain_password=SECRET_GROUP_B,
        settings=settings,
        priority=10,
    )
    set_group_credential(
        db_session,
        rbac_group_id=g_high.id,
        app_slug="transfer",
        robotic_username="sdis81-generic",
        plain_password=SECRET_GROUP,
        settings=settings,
        priority=200,
    )

    resolved, password = resolve_credential(
        db_session,
        "transfer",
        settings,
        KC_USER,
        group_names=["Clients", "SDIS 81"],
    )
    assert resolved.robotic_username == "sdis81-generic"
    assert password == SECRET_GROUP


def test_no_group_names_falls_back_to_app_shared(db_session: Session):
    _make_app(db_session)
    group = _make_group(db_session)
    settings = _settings()
    set_app_credential(db_session, "transfer", "app-robot", SECRET_SHARED, settings)
    set_group_credential(
        db_session,
        rbac_group_id=group.id,
        app_slug="transfer",
        robotic_username="sdis81-generic",
        plain_password=SECRET_GROUP,
        settings=settings,
    )

    resolved, password = resolve_credential(
        db_session, "transfer", settings, KC_USER, group_names=None
    )
    assert resolved.source == "shared"
    assert password == SECRET_SHARED


def test_individual_required_satisfied_by_group_shared(db_session: Session):
    """Portal 'Configuration requise' must not ignore group vault accounts."""
    app = _make_app(db_session)
    app.credential_mode = "individual_required"
    db_session.commit()
    group = _make_group(db_session)
    settings = _settings()
    set_group_credential(
        db_session,
        rbac_group_id=group.id,
        app_slug="transfer",
        robotic_username="sdis81-generic",
        plain_password=SECRET_GROUP,
        settings=settings,
    )

    row, source = get_effective_credential(
        db_session, "transfer", KC_USER, group_names=[GROUP_NAME]
    )
    assert source == "group_shared"
    assert row is not None
    assert (
        needs_individual_credential_setup(
            db_session, app, KC_USER, group_names=[GROUP_NAME]
        )
        is False
    )
    assert needs_individual_credential_setup(db_session, app, KC_USER) is True


def test_individual_required_exclusion_still_needs_setup(db_session: Session):
    app = _make_app(db_session)
    app.credential_mode = "individual_required"
    db_session.commit()
    group = _make_group(db_session)
    settings = _settings()
    cred = set_group_credential(
        db_session,
        rbac_group_id=group.id,
        app_slug="transfer",
        robotic_username="sdis81-generic",
        plain_password=SECRET_GROUP,
        settings=settings,
    )
    add_group_credential_exclusion(db_session, cred.id, KC_USER_EXCL)

    assert (
        needs_individual_credential_setup(
            db_session, app, KC_USER_EXCL, group_names=[GROUP_NAME]
        )
        is True
    )


def test_set_group_credential_keeps_password_when_blank_on_update(db_session: Session):
    _make_app(db_session)
    group = _make_group(db_session)
    settings = _settings()
    cred = set_group_credential(
        db_session,
        rbac_group_id=group.id,
        app_slug="transfer",
        robotic_username="sdis81-generic",
        plain_password=SECRET_GROUP,
        settings=settings,
    )
    old_cipher = cred.encrypted_password
    updated = set_group_credential(
        db_session,
        rbac_group_id=group.id,
        app_slug="transfer",
        robotic_username="sdis81-renamed",
        plain_password="",
        settings=settings,
        priority=50,
    )
    assert updated.robotic_username == "sdis81-renamed"
    assert updated.priority == 50
    assert updated.encrypted_password == old_cipher
