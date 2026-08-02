"""AccessGrant enforcement on /internal/subdomain-auth (audit sessions §6.2)."""

from __future__ import annotations

import respx
from httpx import Response
from sqlalchemy.orm import Session

from app.breakglass import COOKIE_NAME, create_breakglass_token
from app.models import AccessGrant, App, AuditLog, RealmConfig
from app.rbac.grants_service import AccessGrantCreate, create_grant, delete_grant
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings, get_settings


KC_USER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OIDC_URL = "http://127.0.0.1:4180/oauth2/auth"


def _settings(*, rfc1918: bool = False) -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        breakglass_jwt_secret_fallback_enabled=True,
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
        oauth2_proxy_default_url="http://127.0.0.1:4180",
        rfc1918_bypass_enabled=rfc1918,
    )


def _override_settings(client, settings: Settings) -> None:
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings


def _app(db: Session, *, slug: str = "transfer") -> App:
    app = App(
        slug=slug,
        label=slug.title(),
        upstream_url=f"https://{slug}.internal/",
        enabled=True,
        access_mode="subdomain_proxy",
        public_fqdn=f"{slug}.ar-systems.fr",
        realm_slug="ar-systems",
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def _realm(db: Session) -> RealmConfig:
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


def _oidc_ok(**extra_headers: str) -> Response:
    headers = {
        "X-Auth-Request-User": KC_USER,
        "X-Auth-Request-Email": "alice@example.com",
        "X-Auth-Request-Preferred-Username": "alice",
        "X-Auth-Request-Groups": "",
    }
    headers.update(extra_headers)
    return Response(202, headers=headers)


def _auth_headers(
    host: str = "transfer.ar-systems.fr",
    *,
    uri: str = "/web/",
) -> dict[str, str]:
    return {
        "X-Original-Host": host,
        "X-Original-URI": uri,
        "X-Real-IP": "8.8.8.8",
        "Cookie": "_oauth2_proxy=valid",
    }


@respx.mock
def test_subdomain_auth_launch_grant_allows(client, db_session):
    _override_settings(client, _settings())
    _realm(db_session)
    app = _app(db_session)
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id=KC_USER,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db_session.commit()
    respx.get(OIDC_URL).mock(return_value=_oidc_ok())

    resp = client.get("/internal/subdomain-auth", headers=_auth_headers())
    assert resp.status_code == 200
    assert resp.headers.get("x-auth-app") == "transfer"
    assert resp.headers.get("x-auth-source") == "oidc"


@respx.mock
def test_subdomain_auth_records_app_presence(client, db_session):
    from app.models import ActiveSession

    _override_settings(client, _settings())
    _realm(db_session)
    app = _app(db_session)
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id=KC_USER,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db_session.commit()
    respx.get(OIDC_URL).mock(return_value=_oidc_ok())

    resp = client.get("/internal/subdomain-auth", headers=_auth_headers())
    assert resp.status_code == 200

    row = (
        db_session.query(ActiveSession)
        .filter_by(kind="app", target="transfer", user_email="alice@example.com")
        .one()
    )
    assert (row.details or {}).get("presence_only") is True
    assert (row.details or {}).get("source") == "subdomain_auth"
    assert "session_cookies" not in (row.details or {})


@respx.mock
def test_subdomain_auth_no_grant_returns_403(client, db_session):
    _override_settings(client, _settings())
    _realm(db_session)
    _app(db_session)
    respx.get(OIDC_URL).mock(return_value=_oidc_ok())

    resp = client.get("/internal/subdomain-auth", headers=_auth_headers())
    assert resp.status_code == 403
    assert resp.headers.get("x-auth-error") == "access_denied_no_grant"

    entry = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "access_denied_no_grant")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert entry is not None
    assert entry.target == "transfer"
    assert entry.actor == "alice@example.com"
    assert (entry.details or {}).get("uri") == "/web/"
    assert (entry.details or {}).get("host") == "transfer.ar-systems.fr"


@respx.mock
def test_subdomain_auth_no_app_for_host_is_audited(client, db_session):
    _override_settings(client, _settings())
    _realm(db_session)
    respx.get(OIDC_URL).mock(return_value=_oidc_ok())

    resp = client.get(
        "/internal/subdomain-auth",
        headers={
            "X-Original-Host": "ghost.ar-systems.fr",
            "X-Original-URI": "/secret/",
            "X-Real-IP": "10.0.0.9",
            "Cookie": "ignored=1",
        },
    )
    assert resp.status_code == 401
    assert resp.headers.get("x-auth-error") == "no-app-for-host"

    entry = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "access_denied_no_app")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert entry is not None
    assert entry.target == "ghost.ar-systems.fr"
    assert (entry.details or {}).get("uri") == "/secret/"


@respx.mock
def test_subdomain_auth_view_only_grant_returns_403(client, db_session):
    _override_settings(client, _settings())
    _realm(db_session)
    app = _app(db_session)
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id=KC_USER,
            resource_type="application",
            application_id=app.id,
            access_level="view",
        ),
        "admin",
    )
    db_session.commit()
    respx.get(OIDC_URL).mock(return_value=_oidc_ok())

    resp = client.get("/internal/subdomain-auth", headers=_auth_headers())
    assert resp.status_code == 403


@respx.mock
def test_subdomain_auth_revoked_grant_cuts_access_immediately(client, db_session):
    """Gap fix: cookie still valid, grant removed → 403 without waiting for expiry."""
    _override_settings(client, _settings())
    _realm(db_session)
    app = _app(db_session)
    grant = create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id=KC_USER,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db_session.commit()
    respx.get(OIDC_URL).mock(return_value=_oidc_ok())

    ok = client.get("/internal/subdomain-auth", headers=_auth_headers())
    assert ok.status_code == 200

    delete_grant(db_session, grant.id)
    db_session.commit()

    denied = client.get("/internal/subdomain-auth", headers=_auth_headers())
    assert denied.status_code == 403
    assert denied.headers.get("x-auth-error") == "access_denied_no_grant"


@respx.mock
def test_breakglass_access_grant_without_grant_returns_200(client, db_session):
    """Break-glass emergency admin: full app access without any AccessGrant (2026-07-23)."""
    _override_settings(client, _settings())
    _realm(db_session)
    _app(db_session)
    # Explicit: no AccessGrant rows for this app / user.
    assert db_session.query(AccessGrant).count() == 0
    respx.get(OIDC_URL).mock(return_value=Response(401))
    token = create_breakglass_token("bg-admin", "test-bg-jwt-secret")

    resp = client.get(
        "/internal/subdomain-auth",
        headers={
            "X-Original-Host": "transfer.ar-systems.fr",
            "X-Real-IP": "8.8.8.8",
            "Cookie": f"{COOKIE_NAME}={token}",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("x-auth-source") == "breakglass"
    assert resp.headers.get("x-auth-user") == "bg-admin"


@respx.mock
def test_oauth2_auth_portal_still_ok_without_app_grant(client, db_session):
    """Portal auth_request must not require an application AccessGrant."""
    _override_settings(client, _settings())
    _realm(db_session)
    respx.get(OIDC_URL).mock(return_value=_oidc_ok())

    resp = client.get(
        "/internal/oauth2-auth",
        headers={"Cookie": "_oauth2_proxy=valid"},
    )
    assert resp.status_code == 202


OIDC_SECRET = "oidc-subdomain-hmac-key-32bytes-min!"
COOKIE = "bastion_session"


def _native_settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        breakglass_jwt_secret_fallback_enabled=True,
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.ar-systems.fr",
        database_url="sqlite://",
        oauth2_proxy_default_url="http://127.0.0.1:4180",
        rfc1918_bypass_enabled=False,
        oidc_session_jwt_secret=OIDC_SECRET,
        oidc_session_cookie_name=COOKIE,
        oidc_session_max_age=3600,
        oidc_native_session_enabled_realms="ar-systems",
    )


@respx.mock
def test_subdomain_auth_accepts_native_bastion_session(client, db_session):
    """Native SSO: bastion_session must authorize subdomain apps (not Keycloak)."""
    from app.oidc_bff import issue_oidc_session

    settings = _native_settings()
    _override_settings(client, settings)
    realm = _realm(db_session)
    realm.oidc_native_session_enabled = True
    db_session.commit()
    app = _app(db_session)
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id=KC_USER,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    token, _jti = issue_oidc_session(
        db_session,
        sub=KC_USER,
        username="alice",
        realm="ar-systems",
        secret=OIDC_SECRET,
        max_age=3600,
        email="alice@example.com",
        groups=(),
    )
    db_session.commit()

    oauth_route = respx.get(OIDC_URL).mock(return_value=Response(401))
    resp = client.get(
        "/internal/subdomain-auth",
        headers={
            "X-Original-Host": "transfer.ar-systems.fr",
            "X-Original-URI": "/WebInterface/new-ui/index.html",
            "X-Real-IP": "8.8.8.8",
            "Cookie": f"{COOKIE}={token}",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("x-auth-source") == "oidc-native"
    assert resp.headers.get("x-auth-app") == "transfer"
    assert not oauth_route.called


@respx.mock
def test_subdomain_auth_native_without_grant_returns_403(client, db_session):
    from app.oidc_bff import issue_oidc_session

    settings = _native_settings()
    _override_settings(client, settings)
    realm = _realm(db_session)
    realm.oidc_native_session_enabled = True
    db_session.commit()
    _app(db_session)
    token, _jti = issue_oidc_session(
        db_session,
        sub=KC_USER,
        username="alice",
        realm="ar-systems",
        secret=OIDC_SECRET,
        max_age=3600,
    )
    db_session.commit()

    respx.get(OIDC_URL).mock(return_value=Response(401))
    resp = client.get(
        "/internal/subdomain-auth",
        headers={
            "X-Original-Host": "transfer.ar-systems.fr",
            "X-Original-URI": "/",
            "X-Real-IP": "8.8.8.8",
            "Cookie": f"{COOKIE}={token}",
        },
    )
    assert resp.status_code == 403
    assert resp.headers.get("x-auth-error") == "access_denied_no_grant"


@respx.mock
def test_subdomain_auth_accepts_native_via_x_bastion_session_header(client, db_session):
    """CrushFTP upstream Cookie filter must not starve auth_request of bastion_session."""
    from app.oidc_bff import issue_oidc_session

    settings = _native_settings()
    _override_settings(client, settings)
    realm = _realm(db_session)
    realm.oidc_native_session_enabled = True
    db_session.commit()
    app = _app(db_session)
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id=KC_USER,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    token, _jti = issue_oidc_session(
        db_session,
        sub=KC_USER,
        username="alice",
        realm="ar-systems",
        secret=OIDC_SECRET,
        max_age=3600,
        groups=("ARSYSTEMS-Users",),
    )
    db_session.commit()

    oauth_route = respx.get(OIDC_URL).mock(return_value=Response(401))
    resp = client.get(
        "/internal/subdomain-auth",
        headers={
            "X-Original-Host": "transfer.ar-systems.fr",
            "X-Original-URI": "/WebInterface/new-ui/index.html",
            "X-Real-IP": "8.8.8.8",
            # Simulate auth_request with only CrushAuth in Cookie + explicit header.
            "Cookie": "CrushAuth=abc; currentAuth=def",
            "X-Bastion-Session-Cookie": token,
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("x-auth-source") == "oidc-native"
    assert not oauth_route.called


@respx.mock
def test_subdomain_auth_resolves_app_from_host_header_fallback(client, db_session):
    from app.oidc_bff import issue_oidc_session

    settings = _native_settings()
    _override_settings(client, settings)
    realm = _realm(db_session)
    realm.oidc_native_session_enabled = True
    db_session.commit()
    app = _app(db_session)
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id=KC_USER,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    token, _jti = issue_oidc_session(
        db_session,
        sub=KC_USER,
        username="alice",
        realm="ar-systems",
        secret=OIDC_SECRET,
        max_age=3600,
    )
    db_session.commit()

    respx.get(OIDC_URL).mock(return_value=Response(401))
    resp = client.get(
        "/internal/subdomain-auth",
        headers={
            # No X-Original-Host — edge misconfig; Host is the vhost FQDN.
            "Host": "transfer.ar-systems.fr",
            "X-Original-URI": "/",
            "X-Real-IP": "8.8.8.8",
            "Cookie": f"{COOKIE}={token}",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("x-auth-app") == "transfer"


@respx.mock
def test_subdomain_auth_unauthenticated_sets_no_session_error(client, db_session):
    settings = _native_settings()
    _override_settings(client, settings)
    _realm(db_session)
    _app(db_session)
    respx.get(OIDC_URL).mock(return_value=Response(401))
    resp = client.get(
        "/internal/subdomain-auth",
        headers={
            "X-Original-Host": "transfer.ar-systems.fr",
            "X-Original-URI": "/",
            "X-Real-IP": "8.8.8.8",
        },
    )
    assert resp.status_code == 401
    assert resp.headers.get("x-auth-error") == "no-session"


@respx.mock
def test_har_transfer_loop_crushauth_cookie_x_bastion_session_accepts(
    client, db_session
):
    """
    HAR 2026-08-02: transfer request has CrushAuth + bastion_session; auth_request
    must accept via X-Bastion-Session-Cookie even when Cookie is CrushAuth-only
    (CrushFTP upstream filter must not starve subdomain-auth).
    """
    from app.models import RBACGroup
    from app.oidc_bff import issue_oidc_session

    settings = _native_settings()
    _override_settings(client, settings)
    realm = _realm(db_session)
    realm.oidc_native_session_enabled = True
    db_session.commit()
    app = _app(db_session)
    grp = RBACGroup(name="ARSYSTEMS-Users")
    db_session.add(grp)
    db_session.flush()
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=grp.id,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    token, _jti = issue_oidc_session(
        db_session,
        sub=KC_USER,
        username="alice",
        realm="ar-systems",
        secret=OIDC_SECRET,
        max_age=3600,
        groups=("ARSYSTEMS-Users",),
    )
    db_session.commit()

    oauth_route = respx.get(OIDC_URL).mock(return_value=Response(401))
    # Simulate filtered auth_request Cookie (CrushAuth only) + explicit header.
    resp = client.get(
        "/internal/subdomain-auth",
        headers={
            "X-Original-Host": "transfer.ar-systems.fr",
            "X-Original-URI": "/WebInterface/new-ui/index.html",
            "X-Real-IP": "8.8.8.8",
            "Cookie": "CrushAuth=abc123; currentAuth=def456",
            "X-Bastion-Session-Cookie": token,
        },
    )
    assert resp.status_code == 200, resp.headers
    assert resp.headers.get("x-auth-source") == "oidc-native"
    assert resp.headers.get("x-auth-app") == "transfer"
    assert not oauth_route.called


@respx.mock
def test_har_garbled_starlette_cookie_falls_back_to_x_bastion_header(
    client, db_session
):
    """Invalid candidate must not prevent a later valid bastion_session source."""
    from app.oidc_bff import issue_oidc_session

    settings = _native_settings()
    _override_settings(client, settings)
    realm = _realm(db_session)
    realm.oidc_native_session_enabled = True
    db_session.commit()
    app = _app(db_session)
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id=KC_USER,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    token, _jti = issue_oidc_session(
        db_session,
        sub=KC_USER,
        username="alice",
        realm="ar-systems",
        secret=OIDC_SECRET,
        max_age=3600,
    )
    db_session.commit()

    respx.get(OIDC_URL).mock(return_value=Response(401))
    resp = client.get(
        "/internal/subdomain-auth",
        headers={
            "X-Original-Host": "transfer.ar-systems.fr",
            "X-Original-URI": "/index.html",
            "X-Real-IP": "8.8.8.8",
            # Bad explicit header first in candidate order; Cookie still has the JWT.
            "Cookie": f"bastion_session={token}; CrushAuth=abc",
            "X-Bastion-Session-Cookie": "not-a-valid-jwt",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("x-auth-source") == "oidc-native"
