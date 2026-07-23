"""AccessGrant enforcement on /internal/subdomain-auth (audit sessions §6.2)."""

from __future__ import annotations

import respx
from httpx import Response
from sqlalchemy.orm import Session

from app.breakglass import COOKIE_NAME, create_breakglass_token
from app.models import App, AuditLog, RealmConfig
from app.rbac.grants_service import AccessGrantCreate, create_grant, delete_grant
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings, get_settings


KC_USER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OIDC_URL = "http://127.0.0.1:4180/oauth2/auth"


def _settings(*, rfc1918: bool = False) -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
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


def _auth_headers(host: str = "transfer.ar-systems.fr") -> dict[str, str]:
    return {
        "X-Original-Host": host,
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
def test_subdomain_auth_breakglass_bypasses_grants(client, db_session):
    _override_settings(client, _settings())
    _realm(db_session)
    _app(db_session)
    respx.get(OIDC_URL).mock(return_value=Response(401))
    token = create_breakglass_token("bg-admin", "test-secret")

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
