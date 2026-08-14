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
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def _portal_smtp(db, *, enabled: bool = True):
    from app.models import PortalSettings
    from app.portal_settings_service import PORTAL_SETTINGS_ID, ensure_portal_settings

    s = _settings()
    row = ensure_portal_settings(db, s)
    assert row.id == PORTAL_SETTINGS_ID
    row.smtp_enabled = enabled
    row.smtp_host = "smtp.example.com"
    row.smtp_port = 587
    row.smtp_use_tls = True
    row.smtp_username = "mailer"
    row.smtp_password_encrypted = encrypt_secret("smtp-pass", s)
    row.smtp_from_email = "noreply@example.com"
    row.smtp_from_name = "Bastion"
    db.commit()
    db.refresh(row)
    return row


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


def _form_tokens(client, html: str) -> dict[str, str]:
    """Extract CSRF and a solved ALTCHA payload for the access-request form."""
    from app.security.altcha_service import (
        clear_altcha_replay_for_tests,
        solve_altcha_for_tests,
    )
    from app.security.access_request_throttle import clear_access_request_throttle_for_tests

    clear_altcha_replay_for_tests()
    clear_access_request_throttle_for_tests()
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert csrf, "csrf_token missing"
    challenge_resp = client.get("/auth/altcha/challenge")
    assert challenge_resp.status_code == 200, challenge_resp.text
    challenge = challenge_resp.json()
    return {
        "csrf_token": csrf.group(1),
        "altcha": solve_altcha_for_tests(challenge),
    }


def test_login_shows_access_request_link_when_realm_open(client, db_session):
    _realm(db_session, access_request_enabled=True)
    set_breakglass_password(db_session, "admin", "super-secret-password")
    resp = client.get("/login", headers={"X-Real-IP": "10.0.0.50"})
    assert resp.status_code == 200
    assert 'href="/auth/access-request"' in resp.text
    assert "Demander un accès" in resp.text
    assert "Pas encore de compte" in resp.text


def test_login_shows_access_request_even_without_provisioning(client, db_session):
    """CTA visibility must not depend on Keycloak provisioning readiness."""
    set_breakglass_password(db_session, "admin", "super-secret-password")
    s = _settings()
    realm = RealmConfig(
        slug="clients",
        name="CLIENTS",
        issuer_url=f"{KC_BASE}/realms/CLIENTS",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.test/oauth2/clients/callback",
        oauth2_proxy_port=4182,
        enabled=True,
        provisioning_enabled=False,
        access_request_enabled=True,
        show_on_login=True,
        login_label="Clients/Partenaires",
    )
    db_session.add(realm)
    db_session.commit()
    resp = client.get("/login", headers={"X-Real-IP": "10.0.0.50"})
    assert resp.status_code == 200
    assert "Demander un accès" in resp.text
    assert 'href="/auth/access-request"' in resp.text


def test_access_request_honeypot_skips_persist(client, db_session):
    _realm(db_session)
    get_resp = client.get("/auth/access-request")
    tokens = _form_tokens(client, get_resp.text)
    resp = client.post(
        "/auth/access-request",
        data={
            **tokens,
            "website": "https://spam.example",
            "username": "botuser",
            "email": "bot@example.com",
            "organization": "SpamCo",
        },
        headers={"X-Real-IP": "10.0.0.88"},
    )
    assert resp.status_code == 200
    assert "Demande en cours de traitement" in resp.text
    assert db_session.query(AccessRequest).count() == 0


def test_login_hides_access_request_link_when_closed(client, db_session):
    _realm(db_session, access_request_enabled=False)
    set_breakglass_password(db_session, "admin", "super-secret-password")
    resp = client.get("/login", headers={"X-Real-IP": "10.0.0.50"})
    assert resp.status_code == 200
    assert 'href="/auth/access-request"' not in resp.text


def test_access_request_get_has_no_realm_choice(client, db_session):
    realm = _realm(db_session, access_request_enabled=True)
    resp = client.get("/auth/access-request")
    assert resp.status_code == 200
    assert "Demander un accès" in resp.text
    assert 'name="realm_id"' not in resp.text
    assert "Realm / organisation" not in resp.text
    assert realm.slug not in resp.text
    assert "Vérification" in resp.text or "Validation de sécurité" in resp.text
    assert "altcha-widget" in resp.text
    assert "captcha-panel" in resp.text
    assert "/auth/altcha/challenge" in resp.text
    assert "Combien font" not in resp.text
    assert "Saisie" in resp.text
    assert "access-progress" in resp.text
    assert "Envoyée" in resp.text
    assert "Examen" in resp.text
    assert "Configuré" in resp.text


def test_access_request_captcha_rejects_wrong_answer(client, db_session):
    _realm(db_session)
    get_resp = client.get("/auth/access-request")
    tokens = _form_tokens(client, get_resp.text)
    tokens["altcha"] = "invalid-payload"
    resp = client.post(
        "/auth/access-request",
        data={
            **tokens,
            "username": "badbot",
            "email": "badbot@example.com",
            "organization": "SpamCo",
        },
        headers={"X-Real-IP": "10.0.0.77"},
    )
    assert resp.status_code == 200
    assert "Vérification anti-robot incorrecte" in resp.text
    assert db_session.query(AccessRequest).count() == 0


def test_access_request_submit_creates_pending(client, db_session):
    _realm(db_session)
    _portal_smtp(db_session)
    get_resp = client.get("/auth/access-request")
    tokens = _form_tokens(client, get_resp.text)

    with patch("app.rbac.access_request_service.send_email") as mock_send:
        resp = client.post(
            "/auth/access-request",
            data={
                **tokens,
                "username": "newuser",
                "email": "newuser@example.com",
                "first_name": "New",
                "last_name": "User",
                "organization": "ACME Corp",
                "message": "Please grant access",
            },
            headers={"X-Real-IP": "10.0.0.55"},
        )
    assert resp.status_code == 200
    assert "Demande en cours de traitement" in resp.text
    assert "24" in resp.text
    assert "newuser" in resp.text
    assert "ACME Corp" in resp.text
    assert "Please grant access" in resp.text
    assert "Saisie" in resp.text
    assert "Envoyée" in resp.text
    assert "Examen" in resp.text
    assert "Configuré" in resp.text
    assert 'aria-current="step"' in resp.text
    row = (
        db_session.query(AccessRequest)
        .filter_by(username="newuser", status="pending")
        .first()
    )
    assert row is not None
    assert row.email == "newuser@example.com"
    assert row.realm_id is None
    assert row.organization == "ACME Corp"
    assert mock_send.called


def test_altcha_challenge_endpoint_returns_pow(client, db_session):
    _realm(db_session)
    resp = client.get("/auth/altcha/challenge")
    assert resp.status_code == 200
    body = resp.json()
    assert body["algorithm"] == "SHA-256"
    assert body["challenge"]
    assert body["salt"]
    assert body["signature"]
    assert int(body["maxnumber"]) >= 10000


def test_altcha_payload_is_single_use(client, db_session):
    from app.security.altcha_service import (
        clear_altcha_replay_for_tests,
        solve_altcha_for_tests,
        verify_altcha_payload,
    )

    clear_altcha_replay_for_tests()
    challenge = client.get("/auth/altcha/challenge").json()
    payload = solve_altcha_for_tests(challenge)
    settings = _settings()
    assert verify_altcha_payload(settings, payload) is True
    assert verify_altcha_payload(settings, payload) is False


def test_access_request_reject(client, db_session):
    _realm(db_session)
    row = AccessRequest(
        realm_id=None,
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
        realm_id=None,
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
            data={"realm_id": str(realm.id), "send_credentials": ""},
            follow_redirects=False,
        )
    assert resp.status_code == 302, resp.text
    db_session.refresh(row)
    assert row.status == "approved"
    assert row.realm_id == realm.id
    assert row.bastion_account_id is not None
    account = db_session.query(BastionAccount).filter_by(id=row.bastion_account_id).one()
    assert account.username == "approve1"
    assert account.keycloak_user_id == "kc-ar-1"


def test_access_request_approve_requires_realm(client, db_session):
    _realm(db_session)
    row = AccessRequest(
        realm_id=None,
        username="norealm",
        email="nr@example.com",
        organization="Org",
        status="pending",
    )
    db_session.add(row)
    db_session.commit()
    db_session.refresh(row)

    resp = client.post(
        f"/admin/access-requests/{row.id}/approve",
        headers=ADMIN_HEADERS,
        data={"send_credentials": ""},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    db_session.refresh(row)
    assert row.status == "pending"


def test_smtp_send_email_builds_message():
    from app.mail.smtp_service import send_email
    from app.models import PortalSettings

    s = _settings()
    cfg = PortalSettings(
        id=1,
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
            cfg,
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


def test_smtp_data_error_includes_server_response():
    import smtplib

    from app.mail.smtp_service import SmtpError, send_email
    from app.models import PortalSettings

    s = _settings()
    cfg = PortalSettings(
        id=1,
        smtp_enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_username="u",
        smtp_password_encrypted=encrypt_secret("pw", s),
        smtp_from_email="noreply@example.com",
        smtp_from_name="Bastion",
    )
    fake_smtp = MagicMock()
    fake_smtp.__enter__ = MagicMock(return_value=fake_smtp)
    fake_smtp.__exit__ = MagicMock(return_value=False)
    fake_smtp.send_message.side_effect = smtplib.SMTPDataError(
        550, b"5.7.1 Sender address rejected: not owned by user"
    )
    with patch("app.mail.smtp_service.smtplib.SMTP", return_value=fake_smtp):
        try:
            send_email(
                cfg,
                s,
                to_email="ops@example.com",
                subject="Recap",
                body_text="Body",
            )
            raise AssertionError("expected SmtpError")
        except SmtpError as exc:
            assert exc.smtp_code == 550
            assert "Sender address rejected" in str(exc)
            assert "rejeté le contenu" in str(exc) or "550" in str(exc)



def test_smtp_connectivity_test_endpoint(client, db_session):
    from app.portal_settings_service import ensure_portal_settings

    s = _settings()
    row = ensure_portal_settings(db_session, s)
    row.smtp_enabled = True
    row.smtp_host = "smtp.example.com"
    row.smtp_port = 587
    row.smtp_use_tls = True
    row.smtp_username = "u"
    row.smtp_password_encrypted = encrypt_secret("pw", s)
    row.smtp_from_email = "from@example.com"
    db_session.commit()

    fake_smtp = MagicMock()
    fake_smtp.__enter__ = MagicMock(return_value=fake_smtp)
    fake_smtp.__exit__ = MagicMock(return_value=False)
    with patch("app.mail.smtp_service.smtplib.SMTP", return_value=fake_smtp):
        resp = client.post(
            "/admin/configuration/smtp/test",
            headers=ADMIN_HEADERS,
            follow_redirects=False,
        )
    assert resp.status_code == 302
    assert "#smtp" in (resp.headers.get("location") or "")
    fake_smtp.noop.assert_called_once()
    fake_smtp.send_message.assert_not_called()

    page = client.get("/admin/configuration", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    assert 'id="configuration-tabs"' in page.text
    assert "Tester la connexion" in page.text


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

    with patch("app.rbac.account_service.send_credentials_email") as mock_mail:
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
def test_reset_password_sso_only_user(client, db_session):
    """Keycloak user without BastionAccount can still be reset from the fiche."""
    realm = _realm(db_session)

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    respx.get(f"{KC_ADMIN}/users/kc-sso-1").respond(
        200,
        json={
            "id": "kc-sso-1",
            "username": "sso.user",
            "email": "sso@example.com",
            "enabled": True,
        },
    )
    reset_route = respx.put(f"{KC_ADMIN}/users/kc-sso-1/reset-password").respond(204)

    with patch("app.rbac.account_service.send_credentials_email") as mock_mail:
        resp = client.post(
            "/admin/rbac/users/reset-password",
            headers={**ADMIN_HEADERS, "Accept": "application/json"},
            data={
                "realm_id": str(realm.id),
                "keycloak_user_id": "kc-sso-1",
                "send_email": "1",
            },
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["emailed"] is True
    assert reset_route.called
    mock_mail.assert_called_once()
    assert mock_mail.call_args.kwargs["to_email"] == "sso@example.com"
    assert mock_mail.call_args.kwargs["username"] == "sso.user"


@respx.mock
def test_user_view_shows_reset_for_sso_only(client, db_session):
    realm = _realm(db_session)
    respx.post(TOKEN_URL).respond(200, json={"access_token": "tok"})
    respx.get(f"{KC_ADMIN}/users/kc-sso-1").respond(
        200,
        json={
            "id": "kc-sso-1",
            "username": "sso.user",
            "email": "sso@example.com",
            "enabled": True,
            "requiredActions": [],
        },
    )
    respx.get(url__regex=rf"{re.escape(KC_ADMIN)}/users/kc-sso-1/groups.*").respond(
        200, json=[]
    )

    resp = client.get(
        f"/admin/rbac/users/view?realm_id={realm.id}&keycloak_user_id=kc-sso-1",
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 200
    assert 'action="/admin/rbac/users/reset-password"' in resp.text
    assert "Réinitialiser" in resp.text


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
