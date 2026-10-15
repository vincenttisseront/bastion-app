"""Gradual application credential renewal worker (disabled by default)."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import AsyncMock

import pytest

from app.bastion.drivers.base_provisioning import (
    PROVISIONING_FAILED,
    PROVISIONING_SUCCESS,
    ProvisioningResult,
)
from app.models import (
    App,
    BastionAccount,
    BastionAccountProvisioning,
    RealmConfig,
    UserAppCredential,
    utcnow,
)
from app.portal_settings_service import ensure_portal_settings
from app.rbac.app_credential_renewal_service import (
    clamp_renewal_fields,
    renew_one_credential,
    run_app_credential_renewal,
    update_app_credential_renewal_settings,
)
from app.secret_crypto import decrypt_secret, encrypt_secret
from app.sso_settings import Settings, get_settings
from app.vault.user_app_credential_service import set_user_credential


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
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def _crush_app(db) -> App:
    app = App(
        slug="crushftp",
        label="CrushFTP",
        upstream_url="https://crush.example.com/",
        enabled=True,
        provisioning_driver="crushftp",
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def _seed_stale_credential(db, *, age_days: int = 120):
    settings = _settings()
    realm = _realm(db)
    app = _crush_app(db)
    account = BastionAccount(
        realm_id=realm.id,
        username="jdoe",
        email="jdoe@example.com",
        organization="ACME",
        status="keycloak_created",
        origin="bastion",
        keycloak_user_id="kc-jdoe",
        created_by="admin@example.com",
    )
    db.add(account)
    db.flush()
    db.add(
        BastionAccountProvisioning(
            bastion_account_id=account.id,
            application_id=app.id,
            driver_name="crushftp",
            status="success",
            detail="ok",
        )
    )
    set_user_credential(
        db,
        "crushftp",
        "kc-jdoe",
        "jdoe",
        "old-password-value",
        settings,
        actor="test",
    )
    cred = (
        db.query(UserAppCredential)
        .filter_by(app_slug="crushftp", keycloak_user_id="kc-jdoe")
        .one()
    )
    old = utcnow() - timedelta(days=age_days)
    cred.rotated_at = old
    cred.created_at = old
    db.commit()
    db.refresh(cred)
    return settings, account, app, cred


def test_clamp_renewal_fields():
    fields = clamp_renewal_fields(
        enabled=False,
        max_age_days=0,
        batch_size=999,
        interval_minutes=1,
    )
    assert fields["app_credential_renewal_enabled"] is False
    # 0 → default 90; batch capped; interval floored to 5.
    assert fields["app_credential_max_age_days"] == 90
    assert fields["app_credential_batch_size"] == 100
    assert fields["app_credential_renewal_interval_minutes"] == 5
    assert (
        clamp_renewal_fields(
            enabled=True, max_age_days=30, batch_size=3, interval_minutes=120
        )["app_credential_max_age_days"]
        == 30
    )


@pytest.mark.asyncio
async def test_run_noop_when_disabled(db_session):
    settings, *_ = _seed_stale_credential(db_session)
    ensure_portal_settings(db_session, settings)
    result = await run_app_credential_renewal(db_session, settings)
    assert result.examined == 0
    assert result.renewed == 0


@pytest.mark.asyncio
async def test_renew_pushes_api_then_vault(db_session, monkeypatch):
    settings, account, app, cred = _seed_stale_credential(db_session)
    update_app_credential_renewal_settings(
        db_session,
        settings,
        actor="admin@example.com",
        enabled=True,
        max_age_days=90,
        batch_size=5,
        interval_minutes=60,
    )

    create = AsyncMock(
        return_value=ProvisioningResult(
            status=PROVISIONING_SUCCESS,
            detail="replaced",
            credential_pushed=True,
        )
    )
    monkeypatch.setattr(
        "app.bastion.drivers.crushftp.CrushFTPProvisioningDriver.create_account",
        create,
    )

    result = await run_app_credential_renewal(db_session, settings)
    assert result.examined == 1
    assert result.renewed == 1
    create.assert_awaited_once()
    pushed = create.await_args.kwargs["credential"]
    assert pushed.password != "old-password-value"

    db_session.refresh(cred)
    assert cred.rotated_at is not None
    assert decrypt_secret(cred.encrypted_password, settings) == pushed.password


@pytest.mark.asyncio
async def test_renew_leaves_vault_on_api_failure(db_session, monkeypatch):
    settings, _account, _app, cred = _seed_stale_credential(db_session)
    before = cred.encrypted_password
    before_rotated = cred.rotated_at

    create = AsyncMock(
        return_value=ProvisioningResult(
            status=PROVISIONING_FAILED,
            detail="CrushFTP down",
            credential_pushed=False,
        )
    )
    monkeypatch.setattr(
        "app.bastion.drivers.crushftp.CrushFTPProvisioningDriver.create_account",
        create,
    )

    ok, detail = await renew_one_credential(db_session, settings, cred)
    assert ok is False
    assert "down" in detail.lower() or "CrushFTP" in detail
    db_session.refresh(cred)
    assert cred.encrypted_password == before
    assert cred.rotated_at == before_rotated


@pytest.mark.asyncio
async def test_force_run_ignores_enabled_flag(db_session, monkeypatch):
    settings, *_ = _seed_stale_credential(db_session)
    row = ensure_portal_settings(db_session, settings)
    row.app_credential_renewal_enabled = False
    db_session.commit()

    create = AsyncMock(
        return_value=ProvisioningResult(
            status=PROVISIONING_SUCCESS,
            detail="ok",
            credential_pushed=True,
        )
    )
    monkeypatch.setattr(
        "app.bastion.drivers.crushftp.CrushFTPProvisioningDriver.create_account",
        create,
    )

    result = await run_app_credential_renewal(
        db_session, settings, force=True
    )
    assert result.renewed == 1


def test_configuration_ui_shows_section_disabled(client, db_session):
    settings = get_settings()
    ensure_portal_settings(db_session, settings)
    resp = client.get(
        "/admin/configuration",
        headers={"X-Email": "admin@example.com", "X-Groups": "portal-admins"},
    )
    assert resp.status_code == 200
    assert "Renouvellement MDP applicatifs" in resp.text
    assert 'name="app_credential_renewal_enabled"' in resp.text
    # Checkbox present but not checked by default.
    assert 'name="app_credential_renewal_enabled" value="on"\n                   checked' not in resp.text
