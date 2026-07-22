"""Fernet application-vault key rotation — transactional re-encrypt."""

from __future__ import annotations

import logging

import pytest
from cryptography.fernet import Fernet
from sqlalchemy.orm import Session

from app.models import App, AppCredential, AuditLog, RealmConfig, UserAppCredential
from app.secret_crypto import decrypt_with_key, encrypt_with_key
from app.vault.key_rotation_service import (
    KeyRotationError,
    rotate_fernet_key,
)

OLD_KEY = Fernet.generate_key().decode()
NEW_KEY = Fernet.generate_key().decode()
PLAIN_APP = "app-secret-never-in-logs"
PLAIN_USER = "user-secret-never-in-logs"
PLAIN_REALM = "realm-oidc-secret-never-in-logs"
PLAIN_COOKIE = "cookie-secret-never-in-logs"
PLAIN_ADMIN = "admin-api-secret-never-in-logs"


def _make_app(db: Session, slug: str = "transfer") -> App:
    app = App(
        slug=slug,
        label="Transfer",
        upstream_url="https://crush.example/",
        robotic_driver="crushftp",
        enabled=True,
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def _seed_encrypted_rows(db: Session) -> None:
    _make_app(db)
    db.add(
        AppCredential(
            app_slug="transfer",
            robotic_username="robot",
            encrypted_password=encrypt_with_key(PLAIN_APP, OLD_KEY),
            is_active=True,
        )
    )
    db.add(
        UserAppCredential(
            app_slug="transfer",
            keycloak_user_id="kc-user-1",
            robotic_username="user-robot",
            encrypted_password=encrypt_with_key(PLAIN_USER, OLD_KEY),
            is_active=True,
        )
    )
    db.add(
        RealmConfig(
            slug="portal",
            name="Portal",
            issuer_url="https://idp.example/realms/portal",
            client_id="portal-client",
            client_secret_encrypted=encrypt_with_key(PLAIN_REALM, OLD_KEY),
            redirect_uri="https://portal.example/oauth2/callback",
            oauth2_proxy_port=4180,
            oauth2_cookie_secret_encrypted=encrypt_with_key(PLAIN_COOKIE, OLD_KEY),
            keycloak_admin_client_secret_encrypted=encrypt_with_key(PLAIN_ADMIN, OLD_KEY),
            enabled=True,
        )
    )
    db.commit()


def test_rotate_fernet_key_success(db_session: Session):
    _seed_encrypted_rows(db_session)

    report = rotate_fernet_key(db_session, OLD_KEY, NEW_KEY)
    assert report.success is True
    assert report.app_credentials == 1
    assert report.user_app_credentials == 1
    assert report.realm_client_secrets == 1
    assert report.realm_oauth2_cookie_secrets == 1
    assert report.realm_admin_client_secrets == 1
    assert report.total == 5

    app_cred = db_session.query(AppCredential).one()
    user_cred = db_session.query(UserAppCredential).one()
    realm = db_session.query(RealmConfig).one()

    assert decrypt_with_key(app_cred.encrypted_password, NEW_KEY) == PLAIN_APP
    assert decrypt_with_key(user_cred.encrypted_password, NEW_KEY) == PLAIN_USER
    assert decrypt_with_key(realm.client_secret_encrypted, NEW_KEY) == PLAIN_REALM
    assert decrypt_with_key(realm.oauth2_cookie_secret_encrypted, NEW_KEY) == PLAIN_COOKIE
    assert (
        decrypt_with_key(realm.keycloak_admin_client_secret_encrypted, NEW_KEY)
        == PLAIN_ADMIN
    )

    with pytest.raises(ValueError):
        decrypt_with_key(app_cred.encrypted_password, OLD_KEY)
    with pytest.raises(ValueError):
        decrypt_with_key(realm.client_secret_encrypted, OLD_KEY)

    audit = db_session.query(AuditLog).filter_by(action="key_rotation").one()
    assert audit.details["success"] is True
    assert audit.details["total"] == 5
    blob = f"{audit.details}"
    assert PLAIN_APP not in blob
    assert OLD_KEY not in blob
    assert NEW_KEY not in blob


def test_rotate_fernet_key_partial_failure_rolls_back(db_session: Session):
    _seed_encrypted_rows(db_session)
    corrupted = db_session.query(UserAppCredential).one()
    corrupted.encrypted_password = "not-a-valid-fernet-token"
    db_session.commit()

    app_before = db_session.query(AppCredential).one().encrypted_password
    realm_before = db_session.query(RealmConfig).one().client_secret_encrypted

    with pytest.raises(KeyRotationError):
        rotate_fernet_key(db_session, OLD_KEY, NEW_KEY)

    db_session.expire_all()
    app_after = db_session.query(AppCredential).one().encrypted_password
    realm_after = db_session.query(RealmConfig).one().client_secret_encrypted
    assert app_after == app_before
    assert realm_after == realm_before
    assert decrypt_with_key(app_after, OLD_KEY) == PLAIN_APP
    assert decrypt_with_key(realm_after, OLD_KEY) == PLAIN_REALM

    with pytest.raises(ValueError):
        decrypt_with_key(app_after, NEW_KEY)


def test_rotate_rejects_identical_keys(db_session: Session):
    with pytest.raises(KeyRotationError, match="must differ"):
        rotate_fernet_key(db_session, OLD_KEY, OLD_KEY)


def test_rotate_never_logs_secrets(db_session: Session, caplog):
    _seed_encrypted_rows(db_session)
    with caplog.at_level(logging.DEBUG):
        rotate_fernet_key(db_session, OLD_KEY, NEW_KEY)

    joined = "\n".join(r.getMessage() for r in caplog.records)
    for secret in (PLAIN_APP, PLAIN_USER, PLAIN_REALM, PLAIN_COOKIE, PLAIN_ADMIN, OLD_KEY, NEW_KEY):
        assert secret not in joined
