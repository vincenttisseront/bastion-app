"""BastionAccount lifecycle — inactivity warnings, auto-disable, password age."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import AsyncMock

import pytest

from app.models import BastionAccount, PortalSettings, RealmConfig, utcnow
from app.portal_settings_service import ensure_portal_settings
from app.rbac.account_lifecycle_service import (
    DISABLED_REASON_INACTIVITY,
    bastion_directory_stats,
    clamp_lifecycle_fields,
    parse_warn_days,
    run_account_lifecycle,
    touch_bastion_login,
    update_account_lifecycle_settings,
)
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings, get_settings


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.example.com",
        database_url="sqlite://",
    )


def _realm(db) -> RealmConfig:
    s = _settings()
    realm = RealmConfig(
        slug="default",
        name="Default",
        issuer_url="https://idp.example.com/realms/default",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.example.com/oauth2/default/callback",
        oauth2_proxy_port=4180,
        enabled=True,
        groups_sync_enabled=True,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def _account(db, realm: RealmConfig, **kwargs) -> BastionAccount:
    defaults = {
        "realm_id": realm.id,
        "username": "jane.doe",
        "email": "jane.doe@example.com",
        "first_name": "Jane",
        "last_name": "Doe",
        "status": "active",
        "origin": "bastion",
        "keycloak_user_id": "kc-jane",
        "created_by": "test",
    }
    defaults.update(kwargs)
    row = BastionAccount(**defaults)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _enable_lifecycle(db, settings: Settings, **overrides) -> PortalSettings:
    row = ensure_portal_settings(db, settings)
    row.smtp_enabled = True
    row.smtp_host = "smtp.example.com"
    row.smtp_from_email = "noreply@example.com"
    row.account_lifecycle_enabled = True
    row.account_inactivity_days = 180
    row.account_inactivity_warn_days = "30,14,7"
    row.account_password_max_age_days = 90
    row.account_password_warn_days = 14
    for key, value in overrides.items():
        setattr(row, key, value)
    db.commit()
    db.refresh(row)
    return row


def test_parse_warn_days_and_clamp():
    assert parse_warn_days("30,14,7") == [30, 14, 7]
    assert parse_warn_days("7;14;7") == [14, 7]
    fields = clamp_lifecycle_fields(
        enabled=True,
        inactivity_days=10,
        warn_days_raw="30,14,7",
        password_max_age_days=90,
        password_warn_days=100,
    )
    assert fields["account_inactivity_days"] == 30
    assert fields["account_password_warn_days"] < fields["account_password_max_age_days"]


def test_bastion_directory_stats_counts(db_session):
    realm = _realm(db_session)
    _account(db_session, realm, username="a", email="a@example.com", keycloak_user_id="1")
    _account(
        db_session,
        realm,
        username="b",
        email="b@example.com",
        keycloak_user_id="2",
        status="pending",
    )
    _account(
        db_session,
        realm,
        username="c",
        email="c@example.com",
        keycloak_user_id="3",
        disabled_at=utcnow(),
        disabled_reason=DISABLED_REASON_INACTIVITY,
    )
    stats = bastion_directory_stats(db_session)
    assert stats["total"] == 3
    assert stats["pending"] == 1
    assert stats["suspended"] == 1
    assert stats["active"] == 1


def test_touch_bastion_login_clears_inactivity_disable(db_session):
    realm = _realm(db_session)
    account = _account(
        db_session,
        realm,
        disabled_at=utcnow(),
        disabled_reason=DISABLED_REASON_INACTIVITY,
        last_inactivity_warn_stage=7,
    )
    n = touch_bastion_login(
        db_session, keycloak_user_id="kc-jane", email=account.email
    )
    assert n == 1
    db_session.refresh(account)
    assert account.last_login_at is not None
    assert account.disabled_at is None
    assert account.disabled_reason is None


@pytest.mark.asyncio
async def test_run_lifecycle_warns_then_disables(db_session, monkeypatch):
    settings = _settings()
    realm = _realm(db_session)
    _enable_lifecycle(db_session, settings)
    idle = utcnow() - timedelta(days=160)
    account = _account(db_session, realm, last_login_at=idle, created_at=idle)

    sent: list[dict] = []

    def fake_send(portal, settings_arg, *, to_email, subject, body_text, **kwargs):
        sent.append({"to": to_email, "subject": subject, "body": body_text})

    monkeypatch.setattr(
        "app.rbac.account_lifecycle_service.send_email", fake_send
    )

    result = await run_account_lifecycle(db_session, settings)
    assert result.examined == 1
    assert result.inactivity_warnings == 1
    assert result.disabled == 0
    assert sent
    assert "désactivé" in sent[0]["subject"].lower() or "désactivé" in sent[0]["body"]
    db_session.refresh(account)
    assert account.last_inactivity_warn_stage == 30

    # Past threshold → Keycloak disable.
    account.last_login_at = utcnow() - timedelta(days=200)
    account.last_inactivity_warn_stage = 7
    db_session.commit()

    update_kc = AsyncMock()
    monkeypatch.setattr(
        "app.rbac.keycloak_admin.update_keycloak_user", update_kc
    )
    sent.clear()
    result2 = await run_account_lifecycle(db_session, settings)
    assert result2.disabled == 1
    update_kc.assert_awaited()
    db_session.refresh(account)
    assert account.disabled_reason == DISABLED_REASON_INACTIVITY


@pytest.mark.asyncio
async def test_run_lifecycle_password_warn(db_session, monkeypatch):
    settings = _settings()
    realm = _realm(db_session)
    _enable_lifecycle(db_session, settings, account_inactivity_days=365)
    old_pwd = utcnow() - timedelta(days=80)
    account = _account(
        db_session,
        realm,
        last_login_at=utcnow(),
        password_changed_at=old_pwd,
        created_at=old_pwd,
    )

    sent: list[str] = []

    def fake_send(portal, settings_arg, *, to_email, subject, body_text, **kwargs):
        sent.append(subject)

    monkeypatch.setattr(
        "app.rbac.account_lifecycle_service.send_email", fake_send
    )
    monkeypatch.setattr(
        "app.rbac.keycloak_admin.update_keycloak_user", AsyncMock()
    )

    result = await run_account_lifecycle(db_session, settings)
    assert result.password_warnings == 1
    assert any("mot de passe" in s.lower() for s in sent)
    db_session.refresh(account)
    assert account.last_password_warn_at is not None


def test_update_lifecycle_settings_persists(db_session):
    settings = get_settings()
    row = update_account_lifecycle_settings(
        db_session,
        settings,
        actor="admin@example.com",
        enabled=True,
        inactivity_days=180,
        warn_days_raw="30,14,7",
        password_max_age_days=90,
        password_warn_days=14,
    )
    assert row.account_lifecycle_enabled is True
    assert row.account_inactivity_days == 180


def test_configuration_accounts_tab(client, db_session):
    settings = get_settings()
    _enable_lifecycle(db_session, settings)
    resp = client.get(
        "/admin/configuration",
        headers={"X-Email": "admin@example.com", "X-Groups": "portal-admins"},
    )
    assert resp.status_code == 200
    assert "Cycle de vie des comptes" in resp.text
    assert 'id="accounts"' in resp.text

    save = client.post(
        "/admin/configuration/accounts",
        headers={"X-Email": "admin@example.com", "X-Groups": "portal-admins"},
        data={
            "account_lifecycle_enabled": "on",
            "account_inactivity_days": "180",
            "account_inactivity_warn_days": "30,14,7",
            "account_password_max_age_days": "90",
            "account_password_warn_days": "14",
        },
        follow_redirects=False,
    )
    assert save.status_code == 302
    assert "#accounts" in save.headers.get("location", "")
