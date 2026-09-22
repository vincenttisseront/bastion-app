"""Coverage for profile security helpers."""

from __future__ import annotations

from app.models import RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings
from app.web.profile_security_service import (
    password_self_service_available,
    resolve_user_realm,
)
from app.web.user_context import UserContext


def _settings() -> Settings:
    return Settings(
        sso_portal_default_realm_slug="default",
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
    )


def _user(**extra) -> UserContext:
    base = dict(
        email="alice@example.com",
        username="alice",
        groups=[],
        realm_slug="default",
        auth_source="sso",
        is_admin=False,
        keycloak_user_id="kc-alice",
    )
    base.update(extra)
    return UserContext(**base)


def _realm(db, *, issuer_url: str = "https://idp.example.com/realms/default") -> RealmConfig:
    settings = _settings()
    realm = RealmConfig(
        slug="default",
        name="Default",
        enabled=True,
        issuer_url=issuer_url,
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", settings),
        redirect_uri="https://portal.example.com/oauth2/default/callback",
        oauth2_proxy_port=4180,
        is_default=True,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def test_resolve_user_realm_breakglass_and_slug(db_session):
    settings = _settings()
    assert (
        resolve_user_realm(
            db_session, _user(auth_source="breakglass"), settings
        )
        is None
    )
    assert (
        resolve_user_realm(db_session, _user(keycloak_user_id=""), settings)
        is None
    )

    _realm(db_session)
    found = resolve_user_realm(db_session, _user(realm_slug="default"), settings)
    assert found is not None
    assert found.slug == "default"


def test_password_self_service_unavailable_without_issuer(db_session, monkeypatch):
    settings = _settings()
    _realm(db_session, issuer_url="")
    monkeypatch.setattr(
        "app.web.profile_security_service.manage_users_configured",
        lambda *_a, **_k: True,
    )
    assert password_self_service_available(db_session, _user(), settings) is False
