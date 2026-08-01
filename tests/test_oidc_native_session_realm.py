"""Per-realm OIDC native session flag (pilot rollout)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
import respx
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy.orm import Session

from app.models import AuditLog, RealmConfig
from app.oidc_bff import issue_oidc_session
from app.oidc_bff_client import LoginStepResult, OidcTokenResult
from app.oidc_native_session import is_oidc_native_session_enabled_for_realm
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings, get_settings


OIDC_SECRET = "oidc-pilot-hmac-key-32bytes-min!!!"
COOKIE = "bastion_session"
ADMIN = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
}


def _settings(**extra) -> Settings:
    base = dict(
        environment="test",
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret-different",
        breakglass_jwt_secret_fallback_enabled=True,
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        oauth2_proxy_default_url="http://127.0.0.1:4180",
        oidc_session_jwt_secret=OIDC_SECRET,
        oidc_session_cookie_name=COOKIE,
        oidc_session_max_age=3600,
        sso_portal_default_realm_slug="ar-systems",
        oidc_native_session_enabled_realms="",
    )
    base.update(extra)
    return Settings(**base)


@pytest.fixture()
def pilot_settings(monkeypatch):
    settings = _settings()
    get_settings.cache_clear()
    monkeypatch.setattr("app.oidc_bff.get_settings", lambda: settings)
    monkeypatch.setattr("app.auth.get_settings", lambda: settings)
    from app.main import app

    app.dependency_overrides[get_settings] = lambda: settings
    yield settings
    app.dependency_overrides.pop(get_settings, None)
    get_settings.cache_clear()


def _add_realm(db: Session, *, slug: str, is_default: bool = False, native: bool = False, port: int = 4180) -> RealmConfig:
    seed = _settings()
    realm = RealmConfig(
        slug=slug,
        name=slug.upper(),
        issuer_url=f"https://kc.example/realms/{slug}",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", seed),
        redirect_uri=f"https://portal.example/oauth2/{slug}/callback",
        oauth2_proxy_port=port,
        is_default=is_default,
        enabled=True,
        last_test_status="ok",
        oidc_native_session_enabled=native,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def test_helper_db_flag_and_csv(db_session: Session, pilot_settings: Settings):
    _add_realm(db_session, slug="ar-systems", is_default=True, native=False, port=4180)
    pilot = _add_realm(db_session, slug="pilot-clients", native=True, port=4181)

    assert not is_oidc_native_session_enabled_for_realm(
        db_session, "ar-systems", pilot_settings
    )
    assert is_oidc_native_session_enabled_for_realm(
        db_session, "pilot-clients", pilot_settings
    )

    # CSV bootstrap without DB flag
    pilot.oidc_native_session_enabled = False
    db_session.commit()
    csv_settings = _settings(oidc_native_session_enabled_realms="pilot-clients, other")
    assert is_oidc_native_session_enabled_for_realm(
        db_session, "pilot-clients", csv_settings
    )
    assert not is_oidc_native_session_enabled_for_realm(
        db_session, "ar-systems", csv_settings
    )


@respx.mock
def test_oauth2_auth_ignores_bastion_session_for_non_pilot_realm(
    client: TestClient, db_session: Session, pilot_settings: Settings
):
    _add_realm(db_session, slug="ar-systems", is_default=True, native=False, port=4180)
    token, _jti = issue_oidc_session(
        db_session,
        sub="kc-sub",
        username="alice",
        realm="ar-systems",
        secret=OIDC_SECRET,
        max_age=3600,
    )
    db_session.commit()

    route = respx.get("http://127.0.0.1:4180/oauth2/auth").mock(
        return_value=Response(401)
    )
    client.cookies.set(COOKIE, token)
    resp = client.get("/internal/oauth2-auth")
    assert route.called
    assert resp.status_code == 401


@respx.mock
def test_oauth2_auth_accepts_bastion_session_for_pilot_realm(
    client: TestClient, db_session: Session, pilot_settings: Settings
):
    _add_realm(db_session, slug="ar-systems", is_default=True, native=False, port=4180)
    _add_realm(db_session, slug="pilot-clients", native=True, port=4181)
    token, _jti = issue_oidc_session(
        db_session,
        sub="kc-sub-pilot",
        username="bob",
        realm="pilot-clients",
        secret=OIDC_SECRET,
        max_age=3600,
    )
    db_session.commit()

    route = respx.get("http://127.0.0.1:4180/oauth2/auth").mock(
        return_value=Response(401)
    )
    client.cookies.set(COOKIE, token)
    resp = client.get("/internal/oauth2-auth")
    assert not route.called
    assert resp.status_code == 200
    assert resp.headers.get("x-auth-request-user") == "kc-sub-pilot"


def test_admin_toggle_audits_enable_disable(
    client: TestClient, db_session: Session, pilot_settings: Settings
):
    realm = _add_realm(db_session, slug="pilot-clients", native=False, port=4182)

    on = client.post(
        f"/admin/realms/{realm.id}/oidc-native-session/enable",
        headers=ADMIN,
        follow_redirects=False,
    )
    assert on.status_code in (200, 302)
    db_session.refresh(realm)
    assert realm.oidc_native_session_enabled is True
    assert (
        db_session.query(AuditLog)
        .filter_by(action="realm.oidc_native_session_enabled", target="pilot-clients")
        .count()
        >= 1
    )

    off = client.post(
        f"/admin/realms/{realm.id}/oidc-native-session/disable",
        headers=ADMIN,
        follow_redirects=False,
    )
    assert off.status_code in (200, 302)
    db_session.refresh(realm)
    assert realm.oidc_native_session_enabled is False
    assert (
        db_session.query(AuditLog)
        .filter_by(action="realm.oidc_native_session_disabled", target="pilot-clients")
        .count()
        >= 1
    )


def test_login_rejects_non_pilot_realm(
    client: TestClient, db_session: Session, pilot_settings: Settings
):
    _add_realm(db_session, slug="ar-systems", is_default=True, native=False, port=4180)
    with patch(
        "app.oidc_bff.start_headless_login",
        new=AsyncMock(
            return_value=LoginStepResult(
                status="success",
                tokens=OidcTokenResult(
                    access_token="a",
                    refresh_token=None,
                    id_token="i",
                    expires_in=60,
                    sub="s",
                    preferred_username="u",
                    claims={},
                ),
            )
        ),
    ) as mocked:
        resp = client.post(
            "/auth/login",
            data={"username": "u", "password": "p", "realm": "ar-systems"},
        )
    assert resp.status_code == 403
    mocked.assert_not_called()
