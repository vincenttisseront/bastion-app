"""Passwordless passkey sign-in — service (real WebAuthn crypto) and routes."""

from __future__ import annotations

import hashlib
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from app.auth.passkey_service import (
    CHALLENGE_COOKIE,
    PURPOSE_LOGIN,
    PasskeyError,
    build_login_options,
    build_registration_options,
    consume_challenge,
    get_or_create_user_handle,
    is_passkey_login_enabled_for_realm,
    issue_challenge,
    list_user_passkeys,
    revoke_passkey,
    verify_and_store_registration,
    verify_login_assertion,
)
from app.auth.webauthn_service import rp_id_and_origin
from app.models import (
    AuditLog,
    BastionAccount,
    OidcSession,
    RealmConfig,
    UserPasskey,
    WebauthnChallenge,
    utcnow,
)
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings, get_settings
from app.testing_framework.throttle import reset_throttles
from tests.conftest import csrf_token_for
from tests.webauthn_soft_authenticator import SoftAuthenticator

OIDC_SECRET = "oidc-passkey-hmac-key-32bytes-min!!"
COOKIE = "bastion_session"
SUB = "kc-sub-passkey-1"
KC_ADMIN = "app.rbac.keycloak_admin"


def _settings(**extra) -> Settings:
    base = dict(
        environment="test",
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret-different",
        breakglass_jwt_secret_fallback_enabled=True,
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        oidc_session_jwt_secret=OIDC_SECRET,
        oidc_session_cookie_name=COOKIE,
        oidc_session_max_age=3600,
        sso_portal_default_realm_slug="default",
    )
    base.update(extra)
    return Settings(**base)  # type: ignore[arg-type]


def _realm(db: Session, settings: Settings, *, slug: str = "default", **flags) -> RealmConfig:
    values = dict(enabled=True, oidc_native_session_enabled=True, passkey_login_enabled=True)
    values.update(flags)
    realm = RealmConfig(
        slug=slug,
        name=slug.upper(),
        issuer_url=f"https://kc.example.com/realms/{slug}",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", settings),
        redirect_uri=f"https://portal.test/oauth2/{slug}/callback",
        oauth2_proxy_port=4180 + db.query(RealmConfig).count(),
        **values,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def _authenticator(settings: Settings, **kw) -> SoftAuthenticator:
    rp_id, origin = rp_id_and_origin(settings)
    return SoftAuthenticator(rp_id=rp_id, origin=origin, **kw)


def _enroll(
    db: Session,
    settings: Settings,
    realm: RealmConfig,
    auth: SoftAuthenticator,
    *,
    sub: str = SUB,
    username: str = "alice",
) -> UserPasskey:
    options, challenge_id = build_registration_options(
        db, settings, realm=realm, sub=sub, username=username
    )
    return verify_and_store_registration(
        db,
        settings,
        realm=realm,
        sub=sub,
        username=username,
        credential=auth.register(options),
        challenge_id=challenge_id,
        name="Mon téléphone",
    )


def _login(db: Session, settings: Settings, auth: SoftAuthenticator, **assert_kw) -> UserPasskey:
    options, challenge_id = build_login_options(db, settings)
    return verify_login_assertion(
        db,
        settings,
        credential=auth.assert_(options, **assert_kw),
        challenge_id=challenge_id,
        client_ip="10.0.0.5",
    )


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    reset_throttles()
    yield
    reset_throttles()


@pytest.fixture()
def svc_settings() -> Settings:
    return _settings(portal_domain="portal.example.com")


# --- Service: registration ------------------------------------------------


def test_registration_stores_public_key_with_random_user_handle(db_session, svc_settings):
    realm = _realm(db_session, svc_settings)
    auth = _authenticator(svc_settings, synced=True)
    options, _cid = build_registration_options(
        db_session, svc_settings, realm=realm, sub=SUB, username="alice@example.com"
    )
    assert options["rp"]["id"] == "portal.example.com"
    assert options["authenticatorSelection"]["residentKey"] == "required"
    assert options["authenticatorSelection"]["userVerification"] == "required"
    handle = base64url_to_bytes(options["user"]["id"])
    assert len(handle) == 32
    assert handle != hashlib.sha256(b"alice@example.com").digest()

    row = _enroll(db_session, svc_settings, realm, auth, username="alice@example.com")
    assert row.credential_id == bytes_to_base64url(auth.credential_id)
    assert row.keycloak_sub == SUB
    assert row.name == "Mon téléphone"
    assert row.backup_eligible is True and row.backup_state is True
    assert row.transports == ["internal", "hybrid"]
    # Same identity keeps the same handle.
    assert get_or_create_user_handle(db_session, realm.id, SUB) == auth.user_handle


def test_registration_excludes_existing_credentials_and_rejects_duplicates(
    db_session, svc_settings
):
    realm = _realm(db_session, svc_settings)
    auth = _authenticator(svc_settings)
    _enroll(db_session, svc_settings, realm, auth)

    options, challenge_id = build_registration_options(
        db_session, svc_settings, realm=realm, sub=SUB, username="alice"
    )
    assert [c["id"] for c in options["excludeCredentials"]] == [
        bytes_to_base64url(auth.credential_id)
    ]
    with pytest.raises(PasskeyError) as exc:
        verify_and_store_registration(
            db_session,
            svc_settings,
            realm=realm,
            sub=SUB,
            username="alice",
            credential=auth.register(options),
            challenge_id=challenge_id,
        )
    assert exc.value.reason == "already_registered"


def test_registration_requires_user_verification(db_session, svc_settings):
    realm = _realm(db_session, svc_settings)
    with pytest.raises(PasskeyError) as exc:
        _enroll(db_session, svc_settings, realm, _authenticator(svc_settings, user_verified=False))
    assert exc.value.reason == "registration_invalid"
    assert db_session.query(UserPasskey).count() == 0


def test_registration_challenge_bound_to_identity(db_session, svc_settings):
    realm = _realm(db_session, svc_settings)
    auth = _authenticator(svc_settings)
    options, challenge_id = build_registration_options(
        db_session, svc_settings, realm=realm, sub=SUB, username="alice"
    )
    with pytest.raises(PasskeyError) as exc:
        verify_and_store_registration(
            db_session,
            svc_settings,
            realm=realm,
            sub="someone-else",
            username="mallory",
            credential=auth.register(options),
            challenge_id=challenge_id,
        )
    assert exc.value.reason == "challenge_invalid"


# --- Service: sign-in -------------------------------------------------------


def test_login_assertion_success_updates_usage(db_session, svc_settings):
    realm = _realm(db_session, svc_settings)
    auth = _authenticator(svc_settings, sign_count=1)
    enrolled = _enroll(db_session, svc_settings, realm, auth)

    options, _ = build_login_options(db_session, svc_settings)
    assert options["allowCredentials"] == []
    assert options["userVerification"] == "required"

    row = _login(db_session, svc_settings, auth)
    assert row.id == enrolled.id
    assert row.sign_count == 2
    assert row.last_used_at is not None
    assert row.last_used_ip == "10.0.0.5"


def test_synced_passkey_with_zero_counter_logs_in_repeatedly(db_session, svc_settings):
    realm = _realm(db_session, svc_settings)
    auth = _authenticator(svc_settings, synced=True)
    _enroll(db_session, svc_settings, realm, auth)
    for _ in range(3):
        assert _login(db_session, svc_settings, auth).sign_count == 0


def test_login_challenge_is_single_use(db_session, svc_settings):
    realm = _realm(db_session, svc_settings)
    auth = _authenticator(svc_settings)
    _enroll(db_session, svc_settings, realm, auth)
    options, challenge_id = build_login_options(db_session, svc_settings)
    credential = auth.assert_(options)
    verify_login_assertion(
        db_session, svc_settings, credential=credential, challenge_id=challenge_id
    )
    with pytest.raises(PasskeyError) as exc:
        verify_login_assertion(
            db_session, svc_settings, credential=credential, challenge_id=challenge_id
        )
    assert exc.value.reason == "challenge_invalid"


def test_expired_or_unknown_challenge_rejected(db_session, svc_settings):
    challenge_id, _ = issue_challenge(db_session, purpose=PURPOSE_LOGIN)
    row = db_session.get(WebauthnChallenge, challenge_id)
    row.expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()
    assert consume_challenge(db_session, challenge_id, purpose=PURPOSE_LOGIN) is None
    assert consume_challenge(db_session, "nope", purpose=PURPOSE_LOGIN) is None
    assert consume_challenge(db_session, "", purpose=PURPOSE_LOGIN) is None
    # A login challenge cannot be spent on the registration purpose.
    other_id, _ = issue_challenge(db_session, purpose=PURPOSE_LOGIN)
    assert consume_challenge(db_session, other_id, purpose="passkey-register") is None


def test_issue_challenge_purges_expired_rows(db_session):
    old_id, _ = issue_challenge(db_session, purpose=PURPOSE_LOGIN)
    db_session.get(WebauthnChallenge, old_id).expires_at = utcnow() - timedelta(minutes=1)
    db_session.commit()
    issue_challenge(db_session, purpose=PURPOSE_LOGIN)
    db_session.expire_all()
    assert db_session.get(WebauthnChallenge, old_id) is None


@pytest.mark.parametrize(
    ("assert_kw", "auth_kw", "reason"),
    [
        ({"origin": "https://evil.example.net"}, {}, "assertion_invalid"),
        ({}, {"user_verified": False}, "assertion_invalid"),
        ({"user_handle": b"\x01" * 32}, {}, "user_handle_mismatch"),
    ],
)
def test_login_assertion_rejections(db_session, svc_settings, assert_kw, auth_kw, reason):
    realm = _realm(db_session, svc_settings)
    auth = _authenticator(svc_settings)
    _enroll(db_session, svc_settings, realm, auth)
    auth.user_verified = auth_kw.get("user_verified", True)
    with pytest.raises(PasskeyError) as exc:
        _login(db_session, svc_settings, auth, **assert_kw)
    assert exc.value.reason == reason


def test_unknown_or_revoked_credential_rejected(db_session, svc_settings):
    realm = _realm(db_session, svc_settings)
    stranger = _authenticator(svc_settings)
    stranger.user_handle = b"\x02" * 32
    with pytest.raises(PasskeyError) as exc:
        _login(db_session, svc_settings, stranger)
    assert exc.value.reason == "unknown_credential"

    auth = _authenticator(svc_settings)
    row = _enroll(db_session, svc_settings, realm, auth)
    revoke_passkey(db_session, row, revoked_by="admin@example.com", reason="lost")
    db_session.commit()
    assert list_user_passkeys(db_session, realm.id, SUB) == []
    with pytest.raises(PasskeyError) as exc:
        _login(db_session, svc_settings, auth)
    assert exc.value.reason == "unknown_credential"


def test_sign_count_regression_flags_cloned_authenticator(db_session, svc_settings):
    realm = _realm(db_session, svc_settings)
    auth = _authenticator(svc_settings, sign_count=5)
    _enroll(db_session, svc_settings, realm, auth)
    assert _login(db_session, svc_settings, auth, sign_count=10).sign_count == 10
    with pytest.raises(PasskeyError) as exc:
        _login(db_session, svc_settings, auth, sign_count=7)
    assert exc.value.reason == "sign_count_regression"
    db_session.expire_all()
    assert db_session.query(UserPasskey).one().sign_count == 10


def test_feature_gate_per_realm(db_session):
    settings = _settings(passkey_login_enabled_realms="pilot")
    on = _realm(db_session, settings, slug="on")
    off = _realm(db_session, settings, slug="off", passkey_login_enabled=False)
    pilot = _realm(db_session, settings, slug="pilot", passkey_login_enabled=False)
    no_native = _realm(db_session, settings, slug="nonative", oidc_native_session_enabled=False)
    disabled = _realm(db_session, settings, slug="disabled", enabled=False)
    assert is_passkey_login_enabled_for_realm(db_session, on, settings)
    assert not is_passkey_login_enabled_for_realm(db_session, off, settings)
    assert is_passkey_login_enabled_for_realm(db_session, pilot, settings)
    assert not is_passkey_login_enabled_for_realm(db_session, no_native, settings)
    assert not is_passkey_login_enabled_for_realm(db_session, disabled, settings)
    assert not is_passkey_login_enabled_for_realm(db_session, None, settings)


# --- Routes -----------------------------------------------------------------


@pytest.fixture()
def pk_settings(client, monkeypatch):
    settings = _settings()
    get_settings.cache_clear()
    monkeypatch.setattr("app.auth.oidc_bff.get_settings", lambda: settings)
    client.app.dependency_overrides[get_settings] = lambda: settings
    yield settings
    client.app.dependency_overrides.pop(get_settings, None)
    get_settings.cache_clear()


def _csrf(client: TestClient, ip: str = "10.0.0.40") -> dict[str, str]:
    return {"X-CSRF-Token": csrf_token_for(client), "X-Real-IP": ip}


def _kc_user(**over) -> dict:
    user = {
        "id": SUB,
        "username": "alice",
        "email": "alice@example.com",
        "enabled": True,
        "requiredActions": [],
    }
    user.update(over)
    return user


def _keycloak(user: dict | None = None, groups: list | None = None, *, error: bool = False):
    if error:
        return (
            patch(f"{KC_ADMIN}.fetch_keycloak_user", new=AsyncMock(side_effect=ValueError("down"))),
            patch(f"{KC_ADMIN}.fetch_user_groups", new=AsyncMock(return_value=[])),
        )
    return (
        patch(f"{KC_ADMIN}.fetch_keycloak_user", new=AsyncMock(return_value=user)),
        patch(
            f"{KC_ADMIN}.fetch_user_groups",
            new=AsyncMock(
                return_value=groups
                if groups is not None
                else [{"name": "portal-users", "path": "/portal-users"}]
            ),
        ),
    )


def _browser_login(client, auth, *, rd: str | None = "/apps/files", ip: str = "10.0.0.40"):
    opts = client.post("/auth/passkey/options", headers=_csrf(client, ip))
    assert opts.status_code == 200, opts.text
    assert CHALLENGE_COOKIE in opts.cookies
    body = {"credential": auth.assert_(opts.json()["options"])}
    if rd is not None:
        body["rd"] = rd
    return client.post("/auth/passkey/verify", json=body, headers=_csrf(client, ip))


def test_route_full_passkey_login_issues_native_session(client, db_session, pk_settings):
    realm = _realm(db_session, pk_settings)
    auth = _authenticator(pk_settings)
    passkey = _enroll(db_session, pk_settings, realm, auth)
    fetch_user, fetch_groups = _keycloak(_kc_user())
    with fetch_user, fetch_groups:
        resp = _browser_login(client, auth)

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "status": "ok",
        "username": "alice",
        "realm": "default",
        "redirect": "/apps/files",
    }
    token = resp.cookies[COOKIE]
    payload = jwt.decode(token, OIDC_SECRET, algorithms=["HS256"], options={"verify_aud": False})
    assert payload["sub"] == SUB
    assert payload["groups"] == ["portal-users"]
    assert payload["email"] == "alice@example.com"
    assert "sid" not in payload  # no Keycloak session behind a passkey login

    row = db_session.query(OidcSession).filter_by(sub=SUB).one()
    assert row.jti == payload["jti"] and row.realm == "default"
    audit = db_session.query(AuditLog).filter_by(action="oidc_login_passkey_success").one()
    assert audit.details["auth_method"] == "passkey"
    assert audit.details["passkey_id"] == passkey.id
    assert audit.actor == "alice"


def test_route_unsafe_rd_falls_back_to_apps(client, db_session, pk_settings):
    realm = _realm(db_session, pk_settings)
    auth = _authenticator(pk_settings)
    _enroll(db_session, pk_settings, realm, auth)
    fetch_user, fetch_groups = _keycloak(_kc_user())
    with fetch_user, fetch_groups:
        resp = _browser_login(client, auth, rd="https://evil.example.net/")
    assert resp.status_code == 200
    assert resp.json()["redirect"] == "/apps"


def test_route_requires_csrf(client, db_session, pk_settings):
    _realm(db_session, pk_settings)
    r = client.post("/auth/passkey/options", headers={"X-Real-IP": "10.0.0.41"})
    assert r.status_code == 403
    r = client.post(
        "/auth/passkey/verify", json={"credential": {}}, headers={"X-Real-IP": "10.0.0.41"}
    )
    assert r.status_code == 403
    assert db_session.query(WebauthnChallenge).count() == 0


def test_route_options_404_when_no_realm_enables_passkeys(client, db_session, pk_settings):
    _realm(db_session, pk_settings, passkey_login_enabled=False)
    r = client.post("/auth/passkey/options", headers=_csrf(client))
    assert r.status_code == 404
    assert db_session.query(WebauthnChallenge).count() == 0


def test_route_realm_disabled_after_enrolment_refused(client, db_session, pk_settings):
    realm = _realm(db_session, pk_settings)
    other = _realm(db_session, pk_settings, slug="other")  # keeps options available
    assert other.passkey_login_enabled
    auth = _authenticator(pk_settings)
    _enroll(db_session, pk_settings, realm, auth)
    realm.passkey_login_enabled = False
    db_session.commit()
    fetch_user, fetch_groups = _keycloak(_kc_user())
    with fetch_user, fetch_groups:
        resp = _browser_login(client, auth)
    assert resp.status_code == 403
    assert COOKIE not in resp.cookies


@pytest.mark.parametrize(
    ("kc_user", "reason"),
    [
        (None, "user_not_found"),
        (_kc_user(enabled=False), "user_disabled"),
    ],
)
def test_route_refuses_missing_or_disabled_keycloak_user(
    client, db_session, pk_settings, kc_user, reason
):
    realm = _realm(db_session, pk_settings)
    auth = _authenticator(pk_settings)
    _enroll(db_session, pk_settings, realm, auth)
    fetch_user, fetch_groups = _keycloak(kc_user)
    with fetch_user, fetch_groups:
        resp = _browser_login(client, auth)
    assert resp.status_code == 401
    assert COOKIE not in resp.cookies
    assert db_session.query(OidcSession).count() == 0
    audit = db_session.query(AuditLog).filter_by(action="oidc_login_passkey_failed").one()
    assert audit.details["reason"] == reason


def test_route_refuses_disabled_bastion_account(client, db_session, pk_settings):
    realm = _realm(db_session, pk_settings)
    db_session.add(
        BastionAccount(
            realm_id=realm.id,
            username="alice",
            email="alice@example.com",
            keycloak_user_id=SUB,
            status="active",
            created_by="admin@example.com",
            disabled_at=utcnow(),
            disabled_reason="admin",
        )
    )
    db_session.commit()
    auth = _authenticator(pk_settings)
    _enroll(db_session, pk_settings, realm, auth)
    fetch_user, fetch_groups = _keycloak(_kc_user())
    with fetch_user, fetch_groups:
        resp = _browser_login(client, auth)
    assert resp.status_code == 401
    assert db_session.query(OidcSession).count() == 0


def test_route_required_action_sends_user_to_password(client, db_session, pk_settings):
    realm = _realm(db_session, pk_settings)
    auth = _authenticator(pk_settings)
    _enroll(db_session, pk_settings, realm, auth)
    fetch_user, fetch_groups = _keycloak(_kc_user(requiredActions=["UPDATE_PASSWORD"]))
    with fetch_user, fetch_groups:
        resp = _browser_login(client, auth)
    assert resp.status_code == 401
    assert "mot de passe" in resp.json()["detail"]
    assert db_session.query(OidcSession).count() == 0


def test_route_fails_closed_when_admin_api_unreachable(client, db_session, pk_settings):
    realm = _realm(db_session, pk_settings)
    auth = _authenticator(pk_settings)
    _enroll(db_session, pk_settings, realm, auth)
    fetch_user, fetch_groups = _keycloak(error=True)
    with fetch_user, fetch_groups:
        resp = _browser_login(client, auth)
    assert resp.status_code == 503
    assert COOKIE not in resp.cookies
    assert db_session.query(OidcSession).count() == 0
    audit = db_session.query(AuditLog).filter_by(action="oidc_login_passkey_failed").one()
    assert audit.details["reason"] == "idp_unavailable"


def test_route_verify_failures_are_throttled(client, db_session, pk_settings):
    _realm(db_session, pk_settings)
    headers = _csrf(client, "10.0.0.50")
    for _ in range(10):
        r = client.post("/auth/passkey/verify", json={"credential": {}}, headers=headers)
        assert r.status_code == 401
    blocked = client.post("/auth/passkey/verify", json={"credential": {}}, headers=headers)
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


def test_route_options_are_throttled_per_ip(client, db_session, pk_settings):
    _realm(db_session, pk_settings)
    headers = _csrf(client, "10.0.0.60")
    for _ in range(30):
        assert client.post("/auth/passkey/options", headers=headers).status_code == 200
    assert client.post("/auth/passkey/options", headers=headers).status_code == 429


def test_password_login_still_works_after_refactor(client, db_session, pk_settings):
    """Shared finalize_native_login keeps the password path's response shape."""
    from app.auth.oidc_bff_client import LoginStepResult, OidcTokenResult

    _realm(db_session, pk_settings)
    tokens = OidcTokenResult(
        access_token="a",
        refresh_token="r",
        id_token="i",
        expires_in=300,
        sub="kc-sub-pw",
        preferred_username="bob",
        claims={"sub": "kc-sub-pw", "sid": "kc-session-1", "groups": ["/staff"]},
        groups=("/staff",),
    )
    with patch(
        "app.auth.oidc_bff.start_headless_login",
        new=AsyncMock(return_value=LoginStepResult(status="success", tokens=tokens)),
    ):
        resp = client.post(
            "/auth/login",
            data={"username": "bob", "password": "pw"},
            headers={"X-Real-IP": "10.0.0.70"},
        )
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "username": "bob", "realm": "default"}
    payload = jwt.decode(
        resp.cookies[COOKIE], OIDC_SECRET, algorithms=["HS256"], options={"verify_aud": False}
    )
    assert payload["sid"] == "kc-session-1"
    assert payload["groups"] == ["staff"]
