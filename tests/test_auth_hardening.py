"""Auth hardening: CSRF on login forms, exact realm lookup, break-glass audience,
OTP attempt budget, Keycloak origin pinning."""

from __future__ import annotations

from datetime import timedelta

import bcrypt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth.breakglass import (
    BREAKGLASS_SESSION_RETENTION_DAYS,
    decode_breakglass_token_with_fallback,
    issue_breakglass_token,
    purge_expired_breakglass_sessions,
)
from app.auth.breakglass_store import set_breakglass_password, verify_breakglass_password
from app.models import BreakGlassSession, OidcLoginAttempt, RealmConfig, utcnow
from app.auth.oidc_bff_client import (
    MAX_OTP_FAILURES,
    InvalidCredentialsError,
    OidcBffError,
    _absolute_action_url,
    _interpret_post_password_response,
    submit_headless_otp,
)
from app.auth.oidc_bff_config_service import OidcBffConfig
from app.auth.oidc_native_session import is_oidc_native_session_enabled_for_realm
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings
from tests.test_auth_login_flow import _add_default_idp

OMIT_CSRF = {"X-Test-Omit-CSRF": "1"}
LAN = {"X-Real-IP": "10.0.0.50"}


def _settings(**overrides) -> Settings:
    base = {
        "environment": "test",
        "portal_domain": "portal.example.com",
        "breakglass_jwt_secret": "test-bg-secret",
        "vault_portal_internal_token": "test-secret",
        "portal_secret_encryption_key": "test-encryption-key-for-pytest-only",
    }
    return Settings(**{**base, **overrides})


# --- CSRF on login forms -----------------------------------------------------


def test_breakglass_form_without_csrf_is_refused(client: TestClient, db_session: Session):
    _add_default_idp(db_session)
    set_breakglass_password(db_session, "admin", "super-secret-password")
    response = client.post(
        "/auth/breakglass",
        data={"username": "admin", "password": "super-secret-password"},
        headers={**LAN, **OMIT_CSRF},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert "bg_session" not in response.cookies
    assert db_session.query(BreakGlassSession).count() == 0


def test_setup_form_without_csrf_is_refused(client: TestClient, db_session: Session):
    response = client.post(
        "/auth/setup",
        data={
            "username": "admin",
            "password": "a-long-enough-password",
            "password_confirm": "a-long-enough-password",
        },
        headers={**LAN, **OMIT_CSRF},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert not verify_breakglass_password(db_session, "admin", "a-long-enough-password")


def test_html_login_without_csrf_is_refused(client: TestClient):
    response = client.post(
        "/auth/login",
        data={"username": "alice", "password": "pw", "realm": "default", "rd": "/apps"},
        headers=OMIT_CSRF,
        follow_redirects=False,
    )
    # HTML login renders every refusal as the login page (status 200).
    assert "rechargez la page" in response.text
    assert "bastion_session" not in response.cookies


def test_html_pages_set_csrf_nonce_cookie(client: TestClient):
    response = client.get("/auth/login", headers=LAN)
    assert "bastion_csrf=" in (response.headers.get("set-cookie") or "")


# --- Realm lookup ------------------------------------------------------------


def test_like_wildcard_slug_does_not_match_realm(db_session: Session):
    settings = _settings(oidc_native_session_enabled_realms="")
    db_session.add(
        RealmConfig(
            slug="default",
            name="Default",
            issuer_url="https://idp.example.com/realms/default",
            client_id="portal",
            client_secret_encrypted=encrypt_secret("secret", settings),
            redirect_uri="https://portal.example.com/oauth2/default/callback",
            oauth2_proxy_port=4180,
            enabled=True,
            oidc_native_session_enabled=True,
        )
    )
    db_session.commit()
    assert is_oidc_native_session_enabled_for_realm(db_session, "DEFAULT", settings)
    assert not is_oidc_native_session_enabled_for_realm(db_session, "%", settings)
    assert not is_oidc_native_session_enabled_for_realm(db_session, "def_ult", settings)


# --- Break-glass -------------------------------------------------------------


def test_custom_breakglass_audience_validates_in_strict_mode(db_session: Session):
    settings = _settings(
        breakglass_jwt_audience="bastion-bg-custom", breakglass_jwt_audience_strict=True
    )
    token, _jti = issue_breakglass_token(
        db_session, "admin", "test-bg-secret", audience="bastion-bg-custom"
    )
    payload, _legacy = decode_breakglass_token_with_fallback(token, settings, db=db_session)
    assert payload is not None
    assert payload["aud"] == "bastion-bg-custom"


def test_purge_keeps_chain_while_any_member_is_recent(db_session: Session):
    old = utcnow() - timedelta(days=BREAKGLASS_SESSION_RETENTION_DAYS + 5)
    db_session.add_all(
        [
            BreakGlassSession(jti="a1", chain_id="chain-a", username="admin",
                              issued_at=old, expires_at=old),
            BreakGlassSession(jti="a2", chain_id="chain-a", username="admin",
                              issued_at=utcnow(), expires_at=utcnow() + timedelta(hours=1)),
            BreakGlassSession(jti="b1", chain_id="chain-b", username="admin",
                              issued_at=old, expires_at=old),
            BreakGlassSession(jti="c1", chain_id="", username="admin",
                              issued_at=old, expires_at=old),
        ]
    )
    db_session.commit()
    assert purge_expired_breakglass_sessions(db_session) == 2
    remaining = {row.jti for row in db_session.query(BreakGlassSession).all()}
    assert remaining == {"a1", "a2"}


def test_legacy_admin_hash_ignored_once_an_account_exists(db_session: Session):
    db_session.execute(text("CREATE TABLE IF NOT EXISTS settings (key TEXT, value_json TEXT)"))
    legacy = bcrypt.hashpw(b"legacy-password-12", bcrypt.gensalt(4)).decode()
    db_session.execute(
        text("INSERT INTO settings (key, value_json) VALUES ('breakglass_password_hash', :v)"),
        {"v": legacy},
    )
    db_session.commit()
    set_breakglass_password(db_session, "root", "CorrectHorseBattery1")
    assert not verify_breakglass_password(db_session, "admin", "legacy-password-12")
    assert verify_breakglass_password(db_session, "root", "CorrectHorseBattery1")


# --- OTP attempts ------------------------------------------------------------


def _attempt(db: Session, settings: Settings, *, failures: int = 0, client_id: str = "bff"):
    row = OidcLoginAttempt(
        attempt_id="att-1",
        realm="default",
        username="alice",
        keycloak_cookies_encrypted=encrypt_secret("[]", settings),
        otp_form_encrypted=encrypt_secret(
            '{"kind":"otp","action":"/realms/default/login-actions/authenticate",'
            '"fields":{}}',
            settings,
        ),
        code_verifier="v",
        state="s",
        keycloak_base_url="https://idp.example.com",
        keycloak_realm="default",
        client_id=client_id,
        redirect_uri="https://portal.example.com/cb",
        otp_failures=failures,
        created_at=utcnow(),
        expires_at=utcnow() + timedelta(minutes=5),
    )
    db.add(row)
    db.commit()


@pytest.mark.asyncio
async def test_otp_refused_once_budget_is_spent(db_session: Session):
    settings = _settings()
    _attempt(db_session, settings, failures=MAX_OTP_FAILURES)
    with pytest.raises(InvalidCredentialsError):
        await submit_headless_otp("att-1", "123456", settings=settings, db=db_session)
    assert db_session.query(OidcLoginAttempt).count() == 0


@pytest.mark.asyncio
async def test_otp_refused_when_realm_client_changed(db_session: Session, monkeypatch):
    settings = _settings()
    _attempt(db_session, settings, client_id="old-client")
    monkeypatch.setattr(
        "app.auth.oidc_bff_config_service.get_headless_oidc_config",
        lambda db, realm, s: OidcBffConfig(
            realm_slug="default",
            keycloak_base_url="https://idp.example.com",
            keycloak_realm="default",
            client_id="new-client",
            client_secret="secret",
            redirect_uri="https://portal.example.com/cb",
        ),
    )
    with pytest.raises(InvalidCredentialsError):
        await submit_headless_otp("att-1", "123456", settings=settings, db=db_session)
    assert db_session.query(OidcLoginAttempt).count() == 0


# --- Keycloak navigation -----------------------------------------------------


def test_action_outside_keycloak_origin_is_refused():
    with pytest.raises(OidcBffError):
        _absolute_action_url("https://evil.example.net/collect", "https://idp.example.com")


@pytest.mark.asyncio
async def test_code_redirect_without_state_is_refused():
    import httpx

    resp = httpx.Response(
        302,
        headers={"Location": "https://portal.example.com/cb?code=abc"},
        request=httpx.Request("POST", "https://idp.example.com/realms/default/x"),
    )
    async with httpx.AsyncClient() as client:
        with pytest.raises(OidcBffError, match="State"):
            await _interpret_post_password_response(
                client, resp, expected_state="expected", base="https://idp.example.com"
            )
