"""Passkey lot 4 — security: revocation on account disable / delete, admin view, realm toggle."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth.passkey_service import (
    PasskeyError,
    is_passkey_login_enabled_for_realm,
    list_active_passkeys,
    revoke_user_passkeys,
)
from app.models import AuditLog, BastionAccount, UserPasskey
from app.rbac.account_lifecycle_service import LifecycleRunResult, _disable_for_inactivity
from app.rbac.account_service import delete_bastion_account
from app.sso_settings import get_settings
from tests.conftest import csrf_token_for
from tests.test_passkey_login import (
    SUB,
    _authenticator,
    _enroll,
    _login,
    _realm,
    _settings,
)

ADMIN_HEADERS = {"X-Email": "admin@example.com", "X-Groups": "portal-admins"}
USER_HEADERS = {"X-Email": "bob@example.com", "X-Groups": "portal-users"}


@pytest.fixture()
def settings(client):
    s = _settings()
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: s
    yield s
    client.app.dependency_overrides.pop(get_settings, None)
    get_settings.cache_clear()


def _account(db: Session, realm, *, sub: str = SUB, username: str = "alice") -> BastionAccount:
    account = BastionAccount(
        realm_id=realm.id,
        username=username,
        email=f"{username}@example.com",
        keycloak_user_id=sub,
        status="active",
        created_by="admin@example.com",
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    return account


def _active(db: Session, sub: str = SUB) -> int:
    return db.query(UserPasskey).filter_by(keycloak_sub=sub, revoked=False).count()


def _audit(db: Session, action: str) -> list[AuditLog]:
    return db.query(AuditLog).filter_by(action=action).order_by(AuditLog.id).all()


# --- Service ---------------------------------------------------------------------


def test_revoke_user_passkeys_scopes_to_user_and_realm(db_session, settings):
    realm = _realm(db_session, settings)
    other_realm = _realm(db_session, settings, slug="other")
    auth = _authenticator(settings)
    _enroll(db_session, settings, realm, auth)
    _enroll(db_session, settings, realm, _authenticator(settings))
    _enroll(db_session, settings, other_realm, _authenticator(settings))
    _enroll(db_session, settings, realm, _authenticator(settings), sub="kc-bob", username="bob")

    assert (
        revoke_user_passkeys(db_session, sub=SUB, realm_id=realm.id, revoked_by="t", reason="admin")
        == 2
    )
    db_session.commit()
    assert _active(db_session) == 1  # other realm untouched
    assert _active(db_session, "kc-bob") == 1
    assert revoke_user_passkeys(db_session, sub=SUB, realm_id=None, revoked_by="t", reason="x") == 1
    assert (
        revoke_user_passkeys(db_session, sub="  ", realm_id=None, revoked_by="t", reason="x") == 0
    )


def test_list_active_passkeys_filters(db_session, settings):
    realm = _realm(db_session, settings)
    _enroll(db_session, settings, realm, _authenticator(settings))
    _enroll(db_session, settings, realm, _authenticator(settings), sub="kc-bob", username="bob")
    assert len(list_active_passkeys(db_session)) == 2
    assert [p.username for p in list_active_passkeys(db_session, search="BOB")] == ["bob"]
    assert [p.username for p in list_active_passkeys(db_session, sub=SUB)] == ["alice"]
    assert list_active_passkeys(db_session, search="%") == list_active_passkeys(db_session)


# --- Account lifecycle -------------------------------------------------------------


@pytest.mark.asyncio
async def test_inactivity_disable_revokes_passkeys(db_session, settings):
    realm = _realm(db_session, settings)
    auth = _authenticator(settings)
    _enroll(db_session, settings, realm, auth)
    account = _account(db_session, realm)
    with (
        patch("app.rbac.keycloak_admin.update_keycloak_user", new=AsyncMock()),
        patch("app.rbac.account_lifecycle_service.send_email"),
    ):
        await _disable_for_inactivity(
            db_session,
            settings,
            account,
            realm,
            result=LifecycleRunResult(),
            actor="system:lifecycle",
            idle_days=90,
        )
    assert account.disabled_at is not None
    assert _active(db_session) == 0
    row = db_session.query(UserPasskey).filter_by(keycloak_sub=SUB).one()
    assert row.revoked_reason == "account_disabled"
    [entry] = _audit(db_session, "account.passkeys_revoked")
    assert entry.details["count"] == 1
    # The revoked passkey can no longer sign in.
    with pytest.raises(PasskeyError):
        _login(db_session, settings, auth)


@pytest.mark.asyncio
async def test_inactivity_disable_without_passkeys_logs_nothing_extra(db_session, settings):
    realm = _realm(db_session, settings)
    account = _account(db_session, realm)
    with (
        patch("app.rbac.keycloak_admin.update_keycloak_user", new=AsyncMock()),
        patch("app.rbac.account_lifecycle_service.send_email"),
    ):
        await _disable_for_inactivity(
            db_session,
            settings,
            account,
            realm,
            result=LifecycleRunResult(),
            actor="system:lifecycle",
            idle_days=90,
        )
    assert _audit(db_session, "account.passkeys_revoked") == []


@pytest.mark.asyncio
async def test_account_deletion_revokes_passkeys(db_session, settings):
    realm = _realm(db_session, settings)
    auth = _authenticator(settings)
    _enroll(db_session, settings, realm, auth)
    account = _account(db_session, realm)
    with patch("app.rbac.account_service.delete_keycloak_user", new=AsyncMock(return_value=True)):
        deleted, errors = await delete_bastion_account(
            db_session, settings, account=account, actor="admin@example.com"
        )
    assert deleted is True and errors == []
    assert _active(db_session) == 0
    # Rows are kept (revoked) for audit.
    assert db_session.query(UserPasskey).filter_by(keycloak_sub=SUB).count() == 1
    [entry] = _audit(db_session, "account.deleted")
    assert entry.details["passkeys_revoked"] == 1
    with pytest.raises(PasskeyError):
        _login(db_session, settings, auth)


@pytest.mark.asyncio
async def test_incomplete_deletion_still_revokes_passkeys(db_session, settings):
    realm = _realm(db_session, settings)
    _enroll(db_session, settings, realm, _authenticator(settings))
    account = _account(db_session, realm)
    with patch(
        "app.rbac.account_service.delete_keycloak_user",
        new=AsyncMock(side_effect=ValueError("Keycloak down")),
    ):
        deleted, errors = await delete_bastion_account(
            db_session, settings, account=account, actor="admin@example.com"
        )
    assert deleted is False and errors
    assert db_session.query(BastionAccount).filter_by(id=account.id).first() is not None
    assert _active(db_session) == 0
    [entry] = _audit(db_session, "account.delete_incomplete")
    assert entry.details["passkeys_revoked"] == 1


# --- Admin view --------------------------------------------------------------------


def test_admin_passkeys_page_lists_active_keys(client: TestClient, db_session, settings):
    realm = _realm(db_session, settings)
    _enroll(db_session, settings, realm, _authenticator(settings))
    revoked = _enroll(
        db_session, settings, realm, _authenticator(settings), sub="kc-bob", username="bob"
    )
    revoked.revoked = True
    db_session.commit()
    resp = client.get("/admin/security/passkeys", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "alice" in resp.text
    assert "kc-bob" not in resp.text
    assert "Mon téléphone" in resp.text


def test_admin_passkeys_page_requires_admin(client: TestClient, db_session, settings):
    resp = client.get("/admin/security/passkeys", headers=USER_HEADERS, follow_redirects=False)
    assert resp.status_code in (302, 303, 401, 403)
    assert "Mon téléphone" not in resp.text


def test_admin_revokes_one_passkey(client: TestClient, db_session, settings):
    realm = _realm(db_session, settings)
    auth = _authenticator(settings)
    pk = _enroll(db_session, settings, realm, auth)
    keep = _enroll(db_session, settings, realm, _authenticator(settings))
    resp = client.post(
        f"/admin/security/passkeys/{pk.id}/revoke",
        data={"csrf_token": csrf_token_for(client), "back_q": "alice"},
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/admin/security/passkeys?q=alice"
    db_session.expire_all()
    assert db_session.get(UserPasskey, pk.id).revoked is True
    assert db_session.get(UserPasskey, pk.id).revoked_by == "admin@example.com"
    assert db_session.get(UserPasskey, keep.id).revoked is False
    [entry] = _audit(db_session, "admin.passkey_revoked")
    assert entry.target == f"passkey:{pk.id}"
    with pytest.raises(PasskeyError):
        _login(db_session, settings, auth)


def test_admin_revoke_requires_csrf(client: TestClient, db_session, settings):
    realm = _realm(db_session, settings)
    pk = _enroll(db_session, settings, realm, _authenticator(settings))
    resp = client.post(
        f"/admin/security/passkeys/{pk.id}/revoke",
        data={"csrf_token": "bogus"},
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    db_session.expire_all()
    assert db_session.get(UserPasskey, pk.id).revoked is False
    assert _audit(db_session, "admin.passkey_revoked") == []


def test_admin_revoke_unknown_passkey_404(client: TestClient, db_session, settings):
    resp = client.post(
        "/admin/security/passkeys/9999/revoke",
        data={"csrf_token": csrf_token_for(client)},
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 404


def test_non_admin_cannot_revoke(client: TestClient, db_session, settings):
    realm = _realm(db_session, settings)
    pk = _enroll(db_session, settings, realm, _authenticator(settings))
    resp = client.post(
        f"/admin/security/passkeys/{pk.id}/revoke",
        data={"csrf_token": csrf_token_for(client)},
        headers=USER_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303, 401, 403)
    db_session.expire_all()
    assert db_session.get(UserPasskey, pk.id).revoked is False


def test_admin_revokes_all_keys_of_a_user(client: TestClient, db_session, settings):
    realm = _realm(db_session, settings)
    _enroll(db_session, settings, realm, _authenticator(settings))
    _enroll(db_session, settings, realm, _authenticator(settings))
    _enroll(db_session, settings, realm, _authenticator(settings), sub="kc-bob", username="bob")
    resp = client.post(
        "/admin/security/passkeys/revoke-user",
        data={"csrf_token": csrf_token_for(client), "realm_id": realm.id, "sub": SUB},
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    db_session.expire_all()
    assert _active(db_session) == 0
    assert _active(db_session, "kc-bob") == 1
    [entry] = _audit(db_session, "admin.passkeys_revoked_all")
    assert entry.details["count"] == 2


# --- Realm toggle ------------------------------------------------------------------


def _edit_form(realm, **extra) -> dict:
    return {
        "name": realm.name,
        "issuer_url": realm.issuer_url,
        "client_id": realm.client_id,
        "oauth2_proxy_port": realm.oauth2_proxy_port,
        "scopes": "openid profile email",
        "oidc_mfa_enabled": "1",
        **extra,
    }


def test_realm_edit_form_shows_passkey_toggle(client: TestClient, db_session, settings):
    realm = _realm(db_session, settings)
    resp = client.get(f"/admin/realms/{realm.id}/edit", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert 'name="passkey_login_enabled"' in resp.text


def test_realm_toggle_switches_passkey_login(client: TestClient, db_session, settings):
    realm = _realm(db_session, settings, passkey_login_enabled=False)
    assert not is_passkey_login_enabled_for_realm(db_session, realm, settings)
    pk = _enroll(db_session, settings, realm, _authenticator(settings))

    with patch("app.admin.realms.export_realm_files"):
        on = client.post(
            f"/admin/realms/{realm.id}",
            data=_edit_form(realm, passkey_login_enabled="1"),
            headers={**ADMIN_HEADERS, "Accept": "application/json"},
        )
        assert on.status_code == 200, on.text
        db_session.expire_all()
        assert realm.passkey_login_enabled is True
        assert is_passkey_login_enabled_for_realm(db_session, realm, settings)

        off = client.post(
            f"/admin/realms/{realm.id}",
            data=_edit_form(realm),
            headers={**ADMIN_HEADERS, "Accept": "application/json"},
        )
        assert off.status_code == 200, off.text
    db_session.expire_all()
    assert realm.passkey_login_enabled is False
    assert not is_passkey_login_enabled_for_realm(db_session, realm, settings)
    # Switching off keeps existing passkeys (only their use is blocked).
    assert db_session.get(UserPasskey, pk.id).revoked is False
    toggles = _audit(db_session, "realm.passkey_login_toggled")
    assert [t.details["enabled"] for t in toggles] == [True, False]


def test_realm_save_without_change_does_not_audit_toggle(client: TestClient, db_session, settings):
    realm = _realm(db_session, settings, passkey_login_enabled=True)
    with patch("app.admin.realms.export_realm_files"):
        resp = client.post(
            f"/admin/realms/{realm.id}",
            data=_edit_form(realm, passkey_login_enabled="1"),
            headers={**ADMIN_HEADERS, "Accept": "application/json"},
        )
    assert resp.status_code == 200, resp.text
    assert _audit(db_session, "realm.passkey_login_toggled") == []
