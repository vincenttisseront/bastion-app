"""Regression: /internal/oauth2-auth must forward X-Auth-Request-* to Nginx."""

import httpx
import respx
from httpx import Response

from app.models import RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings, get_settings


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        breakglass_jwt_secret_fallback_enabled=True,
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
        oauth2_proxy_default_url="http://127.0.0.1:4180",
        rfc1918_bypass_enabled=False,
    )


def _override_settings(client, settings: Settings) -> None:
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings


def _add_default_realm(db) -> RealmConfig:
    settings = _settings()
    realm = RealmConfig(
        slug="ar-systems",
        name="AR-SYSTEMS",
        issuer_url="https://kc.example.com/realms/AR-SYSTEMS",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", settings),
        redirect_uri="https://portal.test/oauth2/ar-systems/callback",
        oauth2_proxy_port=4180,
        is_default=True,
        enabled=True,
        last_test_status="ok",
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


@respx.mock
def test_oauth2_auth_header_forward_propagates_202_identity_headers(client, db_session):
    settings = _settings()
    _override_settings(client, settings)
    _add_default_realm(db_session)

    respx.get("http://127.0.0.1:4180/oauth2/auth").mock(
        return_value=Response(
            202,
            headers={
                "X-Auth-Request-User": "v.tisseront",
                "X-Auth-Request-Email": "vincent.tisseront@ar-systems.fr",
                "X-Auth-Request-Groups": "portal-admins,ARSYSTEMS-Users",
                "X-Auth-Request-Preferred-Username": "vincent.tisseront",
                "Set-Cookie": "_kc_portal_ar=should-not-leak; Path=/",
            },
        )
    )

    resp = client.get(
        "/internal/oauth2-auth",
        headers={"Cookie": "_kc_portal_ar=valid-session"},
    )

    assert resp.status_code == 202
    assert resp.headers.get("x-auth-request-user") == "v.tisseront"
    assert resp.headers.get("x-auth-request-email") == "vincent.tisseront@ar-systems.fr"
    assert resp.headers.get("x-auth-request-groups") == "portal-admins,ARSYSTEMS-Users"
    assert resp.headers.get("x-auth-request-preferred-username") == "vincent.tisseront"
    assert "set-cookie" not in {k.lower() for k in resp.headers.keys()}


@respx.mock
def test_oauth2_auth_header_forward_401_without_identity_headers(client, db_session):
    settings = _settings()
    _override_settings(client, settings)
    _add_default_realm(db_session)
    respx.get("http://127.0.0.1:4180/oauth2/auth").mock(return_value=Response(401))

    resp = client.get("/internal/oauth2-auth")

    assert resp.status_code == 401
    assert resp.headers.get("x-auth-request-user") is None
    assert resp.headers.get("x-auth-request-email") is None
    assert resp.headers.get("x-auth-request-groups") is None


@respx.mock
def test_oauth2_auth_header_forward_request_error_returns_503(client, db_session):
    settings = _settings()
    _override_settings(client, settings)
    _add_default_realm(db_session)
    respx.get("http://127.0.0.1:4180/oauth2/auth").mock(
        side_effect=httpx.ConnectError("oauth2-proxy down")
    )

    resp = client.get("/internal/oauth2-auth")

    assert resp.status_code == 503
    assert resp.headers.get("x-auth-request-email") is None


@respx.mock
def test_oauth2_auth_prefers_sso_over_breakglass_cookie(client, db_session):
    """Leftover bg_session must not hide a valid oauth2 session (/apps steal)."""
    from app.breakglass import create_breakglass_token

    settings = _settings()
    _override_settings(client, settings)
    _add_default_realm(db_session)

    bg_token = create_breakglass_token("admin", settings.breakglass_jwt_secret)
    respx.get("http://127.0.0.1:4180/oauth2/auth").mock(
        return_value=Response(
            202,
            headers={
                "X-Auth-Request-User": "v.tisseront",
                "X-Auth-Request-Email": "vincent.tisseront@ar-systems.fr",
                "X-Auth-Request-Groups": "ARSYSTEMS-Users",
                "X-Auth-Request-Preferred-Username": "vincent.tisseront",
            },
        )
    )

    resp = client.get(
        "/internal/oauth2-auth",
        headers={"Cookie": f"bg_session={bg_token}; _oauth2_proxy=sso-session"},
    )

    assert resp.status_code == 202
    assert resp.headers.get("x-auth-request-email") == "vincent.tisseront@ar-systems.fr"
    assert resp.headers.get("x-auth-source") is None


@respx.mock
def test_oauth2_auth_falls_back_to_breakglass_when_sso_401(client, db_session):
    from app.breakglass import create_breakglass_token

    settings = _settings()
    _override_settings(client, settings)
    _add_default_realm(db_session)

    bg_token = create_breakglass_token("admin", settings.breakglass_jwt_secret)
    respx.get("http://127.0.0.1:4180/oauth2/auth").mock(return_value=Response(401))

    resp = client.get(
        "/internal/oauth2-auth",
        headers={"Cookie": f"bg_session={bg_token}"},
    )

    assert resp.status_code == 200
    assert resp.headers.get("x-auth-source") == "breakglass"


@respx.mock
def test_oauth2_auth_ignores_rfc1918_bypass_even_when_enabled(client, db_session):
    """Traefik/vpcbr 10.5.0.0/16 must not short-circuit portal auth_request."""
    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
        oauth2_proxy_default_url="http://127.0.0.1:4180",
        rfc1918_bypass_enabled=True,
    )
    _override_settings(client, settings)
    _add_default_realm(db_session)
    route = respx.get("http://127.0.0.1:4180/oauth2/auth").mock(
        return_value=Response(
            202,
            headers={"X-Auth-Request-Email": "user@ar-systems.fr"},
        )
    )

    resp = client.get(
        "/internal/oauth2-auth",
        headers={
            "X-Real-IP": "10.5.0.4",
            "Cookie": "_oauth2_proxy=sso-session",
        },
    )

    assert route.called
    assert resp.status_code == 202
    assert resp.headers.get("x-auth-request-email") == "user@ar-systems.fr"


OIDC_SECRET = "oidc-session-hmac-key-32bytes-min!!"


def _settings_native_enabled() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret-different",
        breakglass_jwt_secret_fallback_enabled=True,
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
        oauth2_proxy_default_url="http://127.0.0.1:4180",
        rfc1918_bypass_enabled=False,
        oidc_native_session_enabled_realms="ar-systems",
        oidc_session_jwt_secret=OIDC_SECRET,
        oidc_session_cookie_name="bastion_session",
        oidc_session_max_age=3600,
    )


@respx.mock
def test_oauth2_auth_oauth2_proxy_alone_unchanged(client, db_session):
    """Regression: oauth2-proxy cookie alone still authenticates (flag on or off)."""
    settings = _settings_native_enabled()
    _override_settings(client, settings)
    _add_default_realm(db_session)
    route = respx.get("http://127.0.0.1:4180/oauth2/auth").mock(
        return_value=Response(
            202,
            headers={
                "X-Auth-Request-User": "kc-sub",
                "X-Auth-Request-Email": "alice@example.com",
                "X-Auth-Request-Preferred-Username": "alice",
            },
        )
    )

    resp = client.get(
        "/internal/oauth2-auth",
        headers={"Cookie": "_oauth2_proxy=valid-session"},
    )

    assert route.called
    assert resp.status_code == 202
    assert resp.headers.get("x-auth-request-email") == "alice@example.com"


@respx.mock
def test_oauth2_auth_bastion_session_alone_valid(client, db_session):
    from app.oidc_bff import issue_oidc_session

    settings = _settings_native_enabled()
    _override_settings(client, settings)
    _add_default_realm(db_session)

    token, _jti = issue_oidc_session(
        db_session,
        sub="kc-sub-native",
        username="alice@example.com",
        realm="ar-systems",
        secret=OIDC_SECRET,
        max_age=3600,
        groups=["ARSYSTEMS-Users", "portal-admins"],
        email="alice@example.com",
    )
    db_session.commit()

    route = respx.get("http://127.0.0.1:4180/oauth2/auth").mock(
        return_value=Response(401)
    )

    resp = client.get(
        "/internal/oauth2-auth",
        headers={"Cookie": f"bastion_session={token}"},
    )

    assert not route.called
    assert resp.status_code == 200
    assert resp.headers.get("x-auth-request-user") == "kc-sub-native"
    assert resp.headers.get("x-auth-request-preferred-username") == "alice@example.com"
    assert resp.headers.get("x-auth-request-email") == "alice@example.com"
    assert resp.headers.get("x-auth-request-groups") == "ARSYSTEMS-Users,portal-admins"
    assert resp.headers.get("x-auth-request-realm") == "ar-systems"


@respx.mock
def test_oauth2_auth_bastion_session_without_groups_omits_groups_header(client, db_session):
    """Legacy JWTs without groups still authenticate (user must re-login for grants)."""
    from app.oidc_bff import issue_oidc_session

    settings = _settings_native_enabled()
    _override_settings(client, settings)
    _add_default_realm(db_session)

    token, _jti = issue_oidc_session(
        db_session,
        sub="kc-sub-legacy",
        username="alice",
        realm="ar-systems",
        secret=OIDC_SECRET,
        max_age=3600,
    )
    db_session.commit()

    resp = client.get(
        "/internal/oauth2-auth",
        headers={"Cookie": f"bastion_session={token}"},
    )

    assert resp.status_code == 200
    assert resp.headers.get("x-auth-request-user") == "kc-sub-legacy"
    assert resp.headers.get("x-auth-request-groups") is None


@respx.mock
def test_oauth2_auth_bastion_session_revoked_falls_back_then_401(client, db_session):
    from app.models import OidcSession
    from app.oidc_bff import issue_oidc_session

    settings = _settings_native_enabled()
    _override_settings(client, settings)
    _add_default_realm(db_session)

    token, jti = issue_oidc_session(
        db_session,
        sub="kc-sub-revoked",
        username="alice",
        realm="ar-systems",
        secret=OIDC_SECRET,
        max_age=3600,
    )
    row = db_session.query(OidcSession).filter_by(jti=jti).one()
    row.revoked = True
    db_session.commit()

    route = respx.get("http://127.0.0.1:4180/oauth2/auth").mock(
        return_value=Response(401)
    )

    resp = client.get(
        "/internal/oauth2-auth",
        headers={"Cookie": f"bastion_session={token}"},
    )

    assert route.called
    assert resp.status_code == 401


@respx.mock
def test_oauth2_auth_no_cookies_returns_401(client, db_session):
    settings = _settings_native_enabled()
    _override_settings(client, settings)
    _add_default_realm(db_session)
    respx.get("http://127.0.0.1:4180/oauth2/auth").mock(return_value=Response(401))

    resp = client.get("/internal/oauth2-auth")

    assert resp.status_code == 401


@respx.mock
def test_oauth2_auth_native_disabled_ignores_bastion_session(client, db_session):
    from app.oidc_bff import issue_oidc_session

    settings = _settings()
    assert not (settings.oidc_native_session_enabled_realms or "").strip()
    # Still mint with a known secret so the cookie is structurally valid.
    object.__setattr__(settings, "oidc_session_jwt_secret", OIDC_SECRET)
    _override_settings(client, settings)
    _add_default_realm(db_session)

    token, _jti = issue_oidc_session(
        db_session,
        sub="kc-sub-ignored",
        username="alice",
        realm="ar-systems",
        secret=OIDC_SECRET,
        max_age=3600,
    )
    db_session.commit()

    route = respx.get("http://127.0.0.1:4180/oauth2/auth").mock(
        return_value=Response(401)
    )

    resp = client.get(
        "/internal/oauth2-auth",
        headers={"Cookie": f"bastion_session={token}"},
    )

    assert route.called
    assert resp.status_code == 401
