"""Access-request queue, SMTP credentials mail, Keycloak password reset."""

from __future__ import annotations

import json
import re
from unittest.mock import MagicMock, patch

import respx

from app.breakglass_store import set_breakglass_password
from app.models import AccessRequest, BastionAccount, RBACGroup, RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}

KC_BASE = "https://kc.example.com"
KC_ADMIN = f"{KC_BASE}/admin/realms/AR-SYSTEMS"
TOKEN_URL = f"{KC_BASE}/realms/AR-SYSTEMS/protocol/openid-connect/token"


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )


def _realm(
    db,
    *,
    access_request_enabled: bool = True,
    smtp_enabled: bool = True,
    send_credentials_email: bool = False,
) -> RealmConfig:
    s = _settings()
    realm = RealmConfig(
        slug="ar-systems",
        name="AR-SYSTEMS",
        issuer_url=f"{KC_BASE}/realms/AR-SYSTEMS",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.test/oauth2/ar-systems/callback",
        oauth2_proxy_port=4180,
        enabled=True,
        groups_sync_enabled=True,
        keycloak_admin_client_id="bastion-admin-sync",
        keycloak_admin_client_secret_encrypted=encrypt_secret("sync-secret", s),
        keycloak_provision_client_id="bastion-admin-provision",
        keycloak_provision_client_secret_encrypted=encrypt_secret("prov-secret", s),
        provisioning_enabled=True,
        access_request_enabled=access_request_enabled,
        send_credentials_email=send_credentials_email,
        smtp_enabled=smtp_enabled,
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_username="mailer",
        smtp_password_encrypted=encrypt_secret("smtp-pass", s),
        smtp_from_email="noreply@example.com",
        smtp_from_name="Bastion",
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def _company_group(db, realm: RealmConfig, name: str = "OrgCo") -> RBACGroup:
    group = RBACGroup(
        realm_id=realm.id,
        realm_slug=realm.slug,
        keycloak_group_id="g-org",
        name=name,
        path=f"/{name}",
    )
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


def test_login_shows_access_request_link_when_realm_open(client, db_session):
    _realm(db_session, access_request_enabled=True)
    set_breakglass_password(db_session, "admin", "super-secret-password")
    resp = client.get("/login", headers={"X-Real-IP": "10.0.0.50"})
    assert resp.status_code == 200
    assert 'href="/auth/access-request"' in resp.text
    assert "Demander un accès" in resp.text
    assert "Pas encore de compte" in resp.text


def test_access_request_honeypot_skips_persist(client, db_session):
    realm = _realm(db_session)
    get_resp = client.get("/auth/access-request")
    m = re.search(r'name="csrf_token" value="([^"]+)"', get_resp.text)
    assert m, "csrf_token missing"
    csrf = m.group(1)
    resp = client.post(
        "/auth/access-request",
        data={
            "csrf_token": csrf,
            "realm_id": str(realm.id),
            "website": "https://spam.example",
            "username": "botuser",
            "email": "bot@example.com",
            "organization": "SpamCo",
        },
        headers={"X-Real-IP": "10.0.0.88"},
    )
    assert resp.status_code == 200
    assert "Demande enregistrée" in resp.text
    assert db_session.query(AccessRequest).count() == 0


def test_login_hides_access_request_link_when_closed(client, db_session):
    _realm(db_session, access_request_enabled=False)
    set_breakglass_password(db_session, "admin", "super-secret-password")
    resp = client.get("/login", headers={"X-Real-IP": "10.0.0.50"})
    assert resp.status_code == 200
    assert 'href="/auth/access-request"' not in resp.text


def test_access_request_get_lists_open_realms(client, db_session):
    realm = _realm(db_session, access_request_enabled=True)
    resp = client.get("/auth/access-request")
    assert resp.status_code == 200
    assert "Demander un accès" in resp.text
    assert str(realm.id) in resp.text
    assert realm.slug in resp.text


def test_access_request_submit_creates_pending(client, db_session):
    realm = _realm(db_session)
    get_resp = client.get("/auth/access-request")
    m = re.search(r'name="csrf_token" value="([^"]+)"', get_resp.text)
    assert m, "csrf_token missing from access-request form"
    csrf = m.group(1)

    with patch("app.rbac.access_request_service.send_email") as mock_send:
        resp = client.post(
            "/auth/access-request",
            data={
                "csrf_token": csrf,
                "realm_id": str(realm.id),
                "username": "newuser",
                "email": "newuser@example.com",
                "first_name": "New",
                "last_name": "User",
                "organization": "ACME Corp",
                "message": "Please grant access",
            },
        )
    assert resp.status_code == 200
    assert "Demande envoyée" in resp.text
    row = (
        db_session.query(AccessRequest)
        .filter_by(username="newuser", status="pending")
        .first()
    )
    assert row is not None
    assert row.email == "newuser@example.com"
    assert row.realm_id == realm.id
    assert row.organization == "ACME Corp"
    assert mock_send.called


def test_access_request_reject(client, db_session):
    realm = _realm(db_session)
    row = AccessRequest(
        realm_id=realm.id,
        username="pending1",
        email="p1@example.com",
        organization="Org",
        status="pending",
    )
    db_session.add(row)
    db_session.commit()
    db_session.refresh(row)

    resp = client.post(
        f"/admin/access-requests/{row.id}/reject",
        headers=ADMIN_HEADERS,
        data={"notes": "nope"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    db_session.refresh(row)
    assert row.status == "rejected"
    assert row.reviewed_by == "admin@example.com"


@respx.mock
def test_access_request_approve_creates_account(client, db_session):
    realm = _realm(db_session)
    _company_group(db_session, realm, name="OrgCo")
    row = AccessRequest(
        realm_id=realm.id,
        username="approve1",
        email="a1@example.com",
        organization="OrgCo",
        first_name="A",
        last_name="One",
        status="pending",
    )
    db_session.add(row)
    db_session.commit()
    db_session.refresh(row)

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    respx.get(
        f"{KC_ADMIN}/users",
        params={"username": "approve1", "exact": "true", "max": "2"},
    ).respond(200, json=[])
    respx.get(
        f"{KC_ADMIN}/users",
        params={"email": "a1@example.com", "exact": "true", "max": "2"},
    ).respond(200, json=[])
    respx.post(f"{KC_ADMIN}/users").respond(
        201, headers={"Location": f"{KC_ADMIN}/users/kc-ar-1"}
    )
    respx.put(f"{KC_ADMIN}/users/kc-ar-1/groups/g-org").respond(204)

    with patch("app.rbac.access_request_service.send_account_credentials_email"):
        resp = client.post(
            f"/admin/access-requests/{row.id}/approve",
            headers=ADMIN_HEADERS,
            data={"send_credentials": ""},
            follow_redirects=False,
        )
    assert resp.status_code == 302, resp.text
    db_session.refresh(row)
    assert row.status == "approved"
    assert row.bastion_account_id is not None
    account = db_session.query(BastionAccount).filter_by(id=row.bastion_account_id).one()
    assert account.username == "approve1"
    assert account.keycloak_user_id == "kc-ar-1"


def test_smtp_send_email_builds_message():
    from app.mail.smtp_service import send_email

    s = _settings()
    realm = RealmConfig(
        slug="x",
        name="X",
        issuer_url="https://kc/realms/x",
        client_id="c",
        redirect_uri="https://p/cb",
        oauth2_proxy_port=4180,
        smtp_enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_username="u",
        smtp_password_encrypted=encrypt_secret("pw", s),
        smtp_from_email="from@example.com",
        smtp_from_name="From Name",
    )
    fake_smtp = MagicMock()
    fake_smtp.__enter__ = MagicMock(return_value=fake_smtp)
    fake_smtp.__exit__ = MagicMock(return_value=False)
    with patch("app.mail.smtp_service.smtplib.SMTP", return_value=fake_smtp) as smtp_cls:
        send_email(
            realm,
            s,
            to_email="user@example.com",
            subject="Hello",
            body_text="Body",
        )
    smtp_cls.assert_called_once_with("smtp.example.com", 587, timeout=20)
    fake_smtp.starttls.assert_called_once()
    fake_smtp.login.assert_called_once_with("u", "pw")
    fake_smtp.send_message.assert_called_once()
    sent = fake_smtp.send_message.call_args[0][0]
    assert sent["To"] == "user@example.com"
    assert sent["Subject"] == "Hello"
    assert "Body" in sent.get_content()
    assert "pw" not in str(sent)


@respx.mock
def test_reset_password_endpoint(client, db_session):
    realm = _realm(db_session)
    account = BastionAccount(
        realm_id=realm.id,
        username="jdoe",
        email="jdoe@example.com",
        keycloak_user_id="kc-user-1",
        status="keycloak_created",
        origin="bastion",
        created_by="admin@example.com",
    )
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    reset_route = respx.put(f"{KC_ADMIN}/users/kc-user-1/reset-password").respond(204)

    with patch("app.rbac.account_service.send_account_credentials_email") as mock_mail:
        resp = client.post(
            f"/admin/rbac/accounts/{account.id}/reset-password",
            headers={**ADMIN_HEADERS, "Accept": "application/json"},
            data={"send_email": "1"},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["emailed"] is True
    assert reset_route.called
    mock_mail.assert_called_once()
    assert "temporaryPassword" not in body
    assert "password" not in body


@respx.mock
def test_verify_email_endpoint(client, db_session):
    realm = _realm(db_session)
    account = BastionAccount(
        realm_id=realm.id,
        username="jdoe",
        email="jdoe@example.com",
        keycloak_user_id="kc-user-1",
        status="keycloak_created",
        origin="bastion",
        created_by="admin@example.com",
    )
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    get_route = respx.get(f"{KC_ADMIN}/users/kc-user-1").respond(
        200,
        json={
            "id": "kc-user-1",
            "username": "jdoe",
            "email": "jdoe@example.com",
            "emailVerified": False,
            "requiredActions": ["VERIFY_EMAIL", "UPDATE_PASSWORD"],
            "enabled": True,
        },
    )
    put_route = respx.put(f"{KC_ADMIN}/users/kc-user-1").respond(204)

    resp = client.post(
        f"/admin/rbac/accounts/{account.id}/verify-email",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True, "email_verified": True}
    assert get_route.called
    assert put_route.called
    body = json.loads(put_route.calls.last.request.content)
    assert body["emailVerified"] is True
    assert "VERIFY_EMAIL" not in body.get("requiredActions", [])
    assert "UPDATE_PASSWORD" in body.get("requiredActions", [])


@respx.mock
def test_require_otp_endpoint(client, db_session):
    realm = _realm(db_session)
    account = BastionAccount(
        realm_id=realm.id,
        username="jdoe",
        email="jdoe@example.com",
        keycloak_user_id="kc-user-1",
        status="keycloak_created",
        origin="bastion",
        created_by="admin@example.com",
    )
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    get_route = respx.get(f"{KC_ADMIN}/users/kc-user-1").respond(
        200,
        json={
            "id": "kc-user-1",
            "username": "jdoe",
            "email": "jdoe@example.com",
            "emailVerified": True,
            "requiredActions": ["UPDATE_PASSWORD"],
            "enabled": True,
        },
    )
    put_route = respx.put(f"{KC_ADMIN}/users/kc-user-1").respond(204)

    resp = client.post(
        f"/admin/rbac/accounts/{account.id}/require-otp",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True, "required_action": "CONFIGURE_TOTP"}
    assert get_route.called
    assert put_route.called
    body = json.loads(put_route.calls.last.request.content)
    assert "CONFIGURE_TOTP" in body.get("requiredActions", [])
    assert "UPDATE_PASSWORD" in body.get("requiredActions", [])


@respx.mock
def test_require_otp_blocked_when_mfa_disabled(client, db_session):
    realm = _realm(db_session)
    realm.oidc_mfa_enabled = False
    db_session.commit()
    account = BastionAccount(
        realm_id=realm.id,
        username="jdoe",
        email="jdoe@example.com",
        keycloak_user_id="kc-user-1",
        status="keycloak_created",
        origin="bastion",
        created_by="admin@example.com",
    )
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)

    resp = client.post(
        f"/admin/rbac/accounts/{account.id}/require-otp",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 400, resp.text
    assert "MFA" in resp.json()["errors"]["_form"]
