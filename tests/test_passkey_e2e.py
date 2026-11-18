"""Passkey sign-in end to end + the invariants it must not bypass.

Covers lots 2–3 on top of ``test_passkey_login.py`` (service + /auth/passkey/*):

- enrolment from the profile, bound to the validated ``bastion_session``, only
  within the re-authentication window;
- password login → enrol → log out → passkey login → ``/internal/oauth2-auth``
  accepts the new session → delete the key → passkey login refused;
- admins still need ``admin_mfa_satisfied`` (no MFA cookie from a passkey);
- no ``@breakglass.local`` identity can enrol or sign in with a passkey;
- SQL bans and failure counters apply to the passkey path.

Real WebAuthn crypto (software authenticator); only Keycloak is mocked.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import AsyncMock, patch

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette.requests import Request as StarletteRequest

from app.auth.mfa_cookie import MFA_COOKIE_NAME
from app.auth.mfa_gate import admin_mfa_satisfied
from app.auth.oidc_bff import issue_oidc_session
from app.auth.passkey_profile import REAUTH_WINDOW, _identity_is_reserved
from app.auth.passkey_service import CHALLENGE_COOKIE
from app.models import (
    AdminMfaCredential,
    AuditLog,
    OidcSession,
    UserPasskey,
    utcnow,
)
from app.security.banning.engine import (
    RULE_FAILED_LOGIN,
    TARGET_IP,
    TARGET_USERNAME,
    apply_ban,
    find_active_ban,
    is_login_path,
)
from app.sso_settings import get_settings
from app.testing_framework.throttle import reset_throttles
from app.web.user_context import UserContext
from tests.conftest import csrf_token_for
from tests.test_passkey_login import (
    COOKIE,
    OIDC_SECRET,
    SUB,
    _authenticator,
    _enroll,
    _kc_user,
    _keycloak,
    _realm,
    _settings,
)

IP = "10.0.0.80"


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    reset_throttles()
    yield
    reset_throttles()


@pytest.fixture()
def e2e(client, monkeypatch):
    settings = _settings()
    get_settings.cache_clear()
    monkeypatch.setattr("app.auth.oidc_bff.get_settings", lambda: settings)
    monkeypatch.setattr("app.auth.auth_request.get_settings", lambda: settings)
    client.app.dependency_overrides[get_settings] = lambda: settings
    yield settings
    client.app.dependency_overrides.pop(get_settings, None)
    get_settings.cache_clear()


def _identity(
    *,
    email: str = "alice@example.com",
    username: str = "alice",
    sub: str = SUB,
    groups: str = "/portal-users",
) -> dict[str, str]:
    """Headers nginx sets after auth_request (trusted via the internal token)."""
    return {
        "X-Email": email,
        "X-Preferred-Username": username,
        "X-User-Id": sub,
        "X-Groups": groups,
        "X-Real-IP": IP,
    }


def _json_headers(client: TestClient, **identity) -> dict[str, str]:
    return {**_identity(**identity), "X-CSRF-Token": csrf_token_for(client)}


def _password_login(client: TestClient, *, sub: str = SUB, username: str = "alice") -> str:
    from app.auth.oidc_bff_client import LoginStepResult, OidcTokenResult

    tokens = OidcTokenResult(
        access_token="a",
        refresh_token="r",
        id_token="i",
        expires_in=300,
        sub=sub,
        preferred_username=username,
        email=f"{username}@example.com",
        claims={"sub": sub, "sid": "kc-session-1", "groups": ["/portal-users"]},
        groups=("/portal-users",),
    )
    with patch(
        "app.auth.oidc_bff.start_headless_login",
        new=AsyncMock(return_value=LoginStepResult(status="success", tokens=tokens)),
    ):
        resp = client.post(
            "/auth/login",
            data={"username": username, "password": "pw"},
            headers={"X-Real-IP": IP},
        )
    assert resp.status_code == 200, resp.text
    return resp.cookies[COOKIE]


def _set_session(client: TestClient, token: str) -> None:
    client.cookies.set(COOKIE, token)


def _drop_session(client: TestClient) -> None:
    client.cookies.delete(COOKIE)


def _register_via_profile(client: TestClient, auth, *, name: str = "Portable", **identity):
    opts = client.post(
        "/profile/passkeys/register/options", headers=_json_headers(client, **identity)
    )
    if opts.status_code != 200:
        return opts
    assert CHALLENGE_COOKIE in opts.cookies
    return client.post(
        "/profile/passkeys/register/verify",
        json={"credential": auth.register(opts.json()["options"]), "name": name},
        headers=_json_headers(client, **identity),
    )


def _passkey_login(client: TestClient, auth, *, ip: str = IP):
    headers = {"X-CSRF-Token": csrf_token_for(client), "X-Real-IP": ip}
    opts = client.post("/auth/passkey/options", headers=headers)
    if opts.status_code != 200:
        return opts
    return client.post(
        "/auth/passkey/verify",
        json={"credential": auth.assert_(opts.json()["options"]), "rd": "/apps"},
        headers=headers,
    )


# --- Full journey -------------------------------------------------------------


def test_e2e_enrol_from_profile_then_passkey_login_then_delete(
    client: TestClient, db_session: Session, e2e
):
    realm = _realm(db_session, e2e)
    _password_login(client)

    page = client.get("/profile", headers=_identity())
    assert page.status_code == 200
    assert 'id="section-passkeys"' in page.text
    assert "data-passkey-register" in page.text

    auth = _authenticator(e2e)
    reg = _register_via_profile(client, auth, name="Portable")
    assert reg.status_code == 200, reg.text
    stored = db_session.query(UserPasskey).one()
    assert (stored.realm_id, stored.keycloak_sub, stored.username) == (realm.id, SUB, "alice")
    assert stored.name == "Portable"
    assert db_session.query(AuditLog).filter_by(action="profile.passkey_registered").count() == 1
    assert "Portable" in client.get("/profile", headers=_identity()).text

    # Log out, sign back in with the passkey only.
    _drop_session(client)
    fetch_user, fetch_groups = _keycloak(_kc_user())
    with fetch_user, fetch_groups:
        login = _passkey_login(client, auth)
    assert login.status_code == 200, login.text
    assert login.json()["redirect"] == "/apps"
    token = login.cookies[COOKIE]
    claims = jwt.decode(token, OIDC_SECRET, algorithms=["HS256"], options={"verify_aud": False})
    assert claims["sub"] == SUB and "sid" not in claims

    # nginx auth_request accepts the passkey-issued session.
    _set_session(client, token)
    gate = client.get("/internal/oauth2-auth")
    assert gate.status_code == 200
    assert gate.headers.get("x-auth-request-user") == SUB

    # Delete the key from the profile → the next passkey sign-in fails.
    deleted = client.post(
        f"/profile/passkeys/{stored.id}/delete",
        data={"csrf_token": csrf_token_for(client)},
        headers=_identity(),
        follow_redirects=False,
    )
    assert deleted.status_code == 302
    db_session.expire_all()
    assert db_session.get(UserPasskey, stored.id).revoked is True
    _drop_session(client)
    fetch_user, fetch_groups = _keycloak(_kc_user())
    with fetch_user, fetch_groups:
        again = _passkey_login(client, auth)
    assert again.status_code == 401
    assert COOKIE not in again.cookies


def test_login_page_offers_passkey_only_when_enabled(client: TestClient, db_session, e2e):
    realm = _realm(db_session, e2e)
    page = client.get("/login")
    assert "data-passkey-login-button" in page.text
    assert 'autocomplete="username webauthn"' in page.text
    assert "bastion-passkey.js" in page.text

    realm.passkey_login_enabled = False
    db_session.commit()
    page = client.get("/login")
    assert "data-passkey-login-button" not in page.text
    assert 'autocomplete="username"' in page.text


# --- Enrolment guards ---------------------------------------------------------


def test_enrolment_requires_recent_login(client: TestClient, db_session, e2e):
    _realm(db_session, e2e)
    _password_login(client)
    row = db_session.query(OidcSession).filter_by(sub=SUB).one()
    row.issued_at = utcnow() - REAUTH_WINDOW - timedelta(minutes=1)
    db_session.commit()

    resp = _register_via_profile(client, _authenticator(e2e))
    assert resp.status_code == 401
    assert resp.json()["reauth"] is True
    assert db_session.query(UserPasskey).count() == 0


def test_enrolment_requires_native_session(client: TestClient, db_session, e2e):
    """oauth2-proxy users (headers only, no bastion_session) cannot enrol."""
    _realm(db_session, e2e)
    resp = _register_via_profile(client, _authenticator(e2e))
    assert resp.status_code == 403
    assert db_session.query(UserPasskey).count() == 0
    assert 'id="section-passkeys"' not in client.get("/profile", headers=_identity()).text


def test_enrolment_refused_when_headers_and_session_disagree(client, db_session, e2e):
    _realm(db_session, e2e)
    _password_login(client)  # session for SUB
    resp = _register_via_profile(client, _authenticator(e2e), sub="kc-sub-someone-else")
    assert resp.status_code == 403
    assert db_session.query(UserPasskey).count() == 0


def test_enrolment_refused_when_realm_disabled(client, db_session, e2e):
    _realm(db_session, e2e, passkey_login_enabled=False)
    _password_login(client)
    resp = _register_via_profile(client, _authenticator(e2e))
    assert resp.status_code == 403


def test_enrolment_requires_csrf(client, db_session, e2e):
    _realm(db_session, e2e)
    _password_login(client)
    resp = client.post("/profile/passkeys/register/options", headers=_identity())
    assert resp.status_code == 403


def test_cannot_delete_someone_elses_passkey(client, db_session, e2e):
    realm = _realm(db_session, e2e)
    other = _enroll(db_session, e2e, realm, _authenticator(e2e), sub="kc-sub-bob", username="bob")
    _password_login(client)
    resp = client.post(
        f"/profile/passkeys/{other.id}/delete",
        data={"csrf_token": csrf_token_for(client)},
        headers=_identity(),
        follow_redirects=False,
    )
    assert resp.status_code == 302
    db_session.expire_all()
    assert db_session.get(UserPasskey, other.id).revoked is False


# --- Break-glass domain -------------------------------------------------------


def test_breakglass_identity_cannot_enrol(client, db_session, e2e):
    realm = _realm(db_session, e2e)
    token, _jti = issue_oidc_session(
        db_session,
        sub="kc-sub-root",
        username="root@breakglass.local",
        realm=realm.slug,
        secret=OIDC_SECRET,
        max_age=3600,
        groups=("portal-admins",),
        email="root@breakglass.local",
    )
    db_session.commit()
    _set_session(client, token)
    resp = _register_via_profile(
        client,
        _authenticator(e2e),
        email="root@corp.example",
        username="root",
        sub="kc-sub-root",
    )
    assert resp.status_code == 403
    assert db_session.query(UserPasskey).count() == 0


def test_breakglass_user_context_is_reserved():
    bg = UserContext(
        email="admin@breakglass.local",
        username="admin",
        groups=["portal-admins"],
        realm_slug="",
        auth_source="breakglass",
        is_admin=True,
    )
    assert _identity_is_reserved(bg, None)
    sso = UserContext(
        email="alice@example.com",
        username="alice",
        groups=[],
        realm_slug="default",
        auth_source="sso",
        is_admin=False,
    )
    assert not _identity_is_reserved(sso, None)


@pytest.mark.parametrize(
    "kc_over",
    [
        {"email": "root@breakglass.local"},
        {"username": "root@breakglass.local", "email": None},
        {"email": "ROOT@BreakGlass.Local"},
    ],
)
def test_passkey_login_refuses_reserved_identity_from_keycloak(client, db_session, e2e, kc_over):
    realm = _realm(db_session, e2e)
    auth = _authenticator(e2e)
    _enroll(db_session, e2e, realm, auth)
    fetch_user, fetch_groups = _keycloak(_kc_user(**kc_over))
    with fetch_user, fetch_groups:
        resp = _passkey_login(client, auth)
    assert resp.status_code == 401
    assert COOKIE not in resp.cookies
    assert db_session.query(OidcSession).count() == 0
    audit = db_session.query(AuditLog).filter_by(action="oidc_login_passkey_failed").one()
    assert audit.details["reason"] == "reserved_identity_domain"


def test_passkey_login_refuses_reserved_stored_username_before_keycloak(client, db_session, e2e):
    realm = _realm(db_session, e2e)
    auth = _authenticator(e2e)
    _enroll(db_session, e2e, realm, auth, username="root@breakglass.local")
    fetch_user, fetch_groups = _keycloak(_kc_user())
    with fetch_user as user_mock, fetch_groups:
        resp = _passkey_login(client, auth)
    assert resp.status_code == 401
    user_mock.assert_not_awaited()
    assert db_session.query(OidcSession).count() == 0


# --- Admin MFA ----------------------------------------------------------------


def test_passkey_login_does_not_satisfy_admin_mfa(client, db_session, e2e):
    realm = _realm(db_session, e2e)
    admin_email = "admin@example.com"
    db_session.add(AdminMfaCredential(user_email=admin_email, totp_enabled=True))
    db_session.commit()
    auth = _authenticator(e2e)
    _enroll(db_session, e2e, realm, auth, sub="kc-sub-admin", username="admin")
    kc = _kc_user(id="kc-sub-admin", username="admin", email=admin_email)
    fetch_user, fetch_groups = _keycloak(
        kc, groups=[{"name": "portal-admins", "path": "/portal-admins"}]
    )
    with fetch_user, fetch_groups:
        resp = _passkey_login(client, auth)
    assert resp.status_code == 200, resp.text
    assert MFA_COOKIE_NAME not in resp.cookies
    claims = jwt.decode(
        resp.cookies[COOKIE], OIDC_SECRET, algorithms=["HS256"], options={"verify_aud": False}
    )
    assert claims["groups"] == ["portal-admins"]

    cookie_header = "; ".join(f"{k}={v}" for k, v in resp.cookies.items())
    request = StarletteRequest(
        {
            "type": "http",
            "method": "GET",
            "path": "/files",
            "query_string": b"",
            "headers": [(b"cookie", cookie_header.encode())],
        }
    )
    admin = UserContext(
        email=admin_email,
        username="admin",
        groups=["portal-admins"],
        realm_slug=realm.slug,
        auth_source="sso",
        is_admin=True,
        keycloak_user_id="kc-sub-admin",
    )
    assert admin_mfa_satisfied(request, admin, db_session, e2e) is False

    # The admin UI itself still sends the admin to the second factor.
    _set_session(client, resp.cookies[COOKIE])
    page = client.get(
        "/admin/apps",
        headers=_identity(
            email=admin_email, username="admin", sub="kc-sub-admin", groups="/portal-admins"
        ),
        follow_redirects=False,
    )
    assert page.status_code in (302, 303)
    assert "/admin/auth/mfa/" in page.headers["location"]


# --- Bans and rate limits ------------------------------------------------------


def test_passkey_paths_are_login_paths_for_the_ban_engine():
    assert is_login_path("/auth/passkey/options", "POST")
    assert is_login_path("/auth/passkey/verify", "POST")


@pytest.mark.parametrize(
    ("ip", "rule_type", "actor"),
    [
        ("203.0.113.7", None, "system"),  # automatic ban, public address
        (IP, "manual", "admin@example.com"),  # admin ban also covers LAN addresses
    ],
)
def test_banned_ip_cannot_use_passkey(client, db_session, e2e, ip, rule_type, actor):
    realm = _realm(db_session, e2e)
    auth = _authenticator(e2e)
    _enroll(db_session, e2e, realm, auth)
    ban = apply_ban(
        db_session,
        target_type=TARGET_IP,
        target=ip,
        reason="test",
        rule_type=rule_type,
        permanent=False,
        ban_minutes=10,
        actor=actor,
    )
    assert ban is not None
    db_session.commit()
    fetch_user, fetch_groups = _keycloak(_kc_user())
    with fetch_user, fetch_groups:
        resp = _passkey_login(client, auth, ip=ip)
    assert resp.status_code == 403
    assert db_session.query(OidcSession).count() == 0


@pytest.mark.parametrize("banned", ["alice", "alice-renamed"])
def test_banned_username_cannot_use_passkey(client, db_session, e2e, banned):
    """A ban on the stored name or on the current Keycloak name blocks the passkey."""
    realm = _realm(db_session, e2e)
    auth = _authenticator(e2e)
    _enroll(db_session, e2e, realm, auth, username="alice")
    apply_ban(
        db_session,
        target_type=TARGET_USERNAME,
        target=banned,
        reason="test",
        rule_type=None,
        permanent=False,
        ban_minutes=10,
    )
    db_session.commit()
    fetch_user, fetch_groups = _keycloak(_kc_user(username="alice-renamed"))
    with fetch_user, fetch_groups:
        resp = _passkey_login(client, auth)
    assert resp.status_code == 403
    assert COOKIE not in resp.cookies
    assert db_session.query(OidcSession).count() == 0


def test_passkey_failures_feed_the_sql_ban_engine(client, db_session, e2e):
    from app.security.banning.service import update_ban_rules

    realm = _realm(db_session, e2e)
    update_ban_rules(
        db_session,
        rules={
            RULE_FAILED_LOGIN: {
                "enabled": True,
                "threshold": 2,
                "window_seconds": 60,
                "ban_minutes": 10,
                "ban_username": True,
            }
        },
        actor="test",
    )
    auth = _authenticator(e2e)
    _enroll(db_session, e2e, realm, auth)
    fetch_user, fetch_groups = _keycloak(_kc_user(enabled=False))
    with fetch_user, fetch_groups:
        first = _passkey_login(client, auth)
        second = _passkey_login(client, auth)
    assert first.status_code == 401
    assert second.status_code == 403
    assert find_active_ban(db_session, username="alice") is not None
    # Even a now-valid account stays blocked while the ban is active.
    fetch_user, fetch_groups = _keycloak(_kc_user())
    with fetch_user, fetch_groups:
        third = _passkey_login(client, auth)
    assert third.status_code == 403
    assert db_session.query(OidcSession).count() == 0


def test_enrolment_options_are_throttled_per_user(client, db_session, e2e):
    from app.auth.passkey_profile import REGISTER_MAX_PER_WINDOW

    _realm(db_session, e2e)
    _password_login(client)
    headers = _json_headers(client)
    for _ in range(REGISTER_MAX_PER_WINDOW):
        assert client.post("/profile/passkeys/register/options", headers=headers).status_code == 200
    assert client.post("/profile/passkeys/register/options", headers=headers).status_code == 429
