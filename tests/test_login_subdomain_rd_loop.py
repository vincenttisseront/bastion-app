"""Prevent portal /login bounce loop with subdomain auth_request 401."""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import App, RealmConfig
from app.oidc_bff import issue_oidc_session
from app.rbac.grants_service import AccessGrantCreate, create_grant
from app.sso_settings import Settings, get_settings
from app.web.user_context import UserContext
from tests.test_auth_login_flow import _add_default_idp

OIDC_SECRET = "oidc-login-loop-hmac-key-32bytes-min!!"
TRANSFER_RD = "https://transfer.ar-systems.fr/WebInterface/new-ui/index.html"
KC_USER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _native_settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        breakglass_jwt_secret_fallback_enabled=True,
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.ar-systems.fr",
        database_url="sqlite://",
        oauth2_proxy_default_url="http://127.0.0.1:4180",
        oidc_session_jwt_secret=OIDC_SECRET,
        oidc_session_cookie_name="bastion_session",
        oidc_session_max_age=3600,
        oidc_native_session_enabled_realms="ar-systems",
    )


def _enable_native_realm(db: Session) -> RealmConfig:
    realm = _add_default_idp(db)
    realm.oidc_native_session_enabled = True
    db.commit()
    return realm


def _transfer_app_with_grant(db: Session, *, groups: tuple[str, ...] = ()) -> App:
    app = App(
        slug="transfer",
        label="Transfer",
        upstream_url="https://transfer.internal/",
        enabled=True,
        access_mode="subdomain_proxy",
        public_fqdn="transfer.ar-systems.fr",
        realm_slug="ar-systems",
        robotic_driver="crushftp",
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    if groups:
        from app.models import RBACGroup

        grp = RBACGroup(name=groups[0])
        db.add(grp)
        db.flush()
        create_grant(
            db,
            AccessGrantCreate(
                subject_type="group",
                rbac_group_id=grp.id,
                resource_type="application",
                application_id=app.id,
                access_level="launch",
            ),
            "admin",
        )
    else:
        create_grant(
            db,
            AccessGrantCreate(
                subject_type="user",
                keycloak_user_id=KC_USER,
                resource_type="application",
                application_id=app.id,
                access_level="launch",
            ),
            "admin",
        )
    db.commit()
    return app


def test_login_with_native_session_bounces_to_subdomain_and_sets_domain(
    client: TestClient, db_session: Session
):
    settings = _native_settings()
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings
    _enable_native_realm(db_session)
    _transfer_app_with_grant(db_session)
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

    resp = client.get(
        f"/auth/login?rd={TRANSFER_RD}",
        cookies={"bastion_session": token},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers.get("location") == TRANSFER_RD
    set_cookie = " ".join(resp.headers.get_list("set-cookie"))
    assert "bastion_session=" in set_cookie
    assert "Domain=ar-systems.fr" in set_cookie or "domain=ar-systems.fr" in set_cookie


def test_login_native_session_without_transfer_grant_goes_to_apps(
    client: TestClient, db_session: Session
):
    """HAR harden: valid bastion_session alone must not bounce when subdomain-auth would 403/401."""
    settings = _native_settings()
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings
    _enable_native_realm(db_session)
    # App exists but no AccessGrant — subdomain-auth would 403; login must not loop.
    db_session.add(
        App(
            slug="transfer",
            label="Transfer",
            upstream_url="https://transfer.internal/",
            enabled=True,
            access_mode="subdomain_proxy",
            public_fqdn="transfer.ar-systems.fr",
            realm_slug="ar-systems",
        )
    )
    db_session.commit()
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

    resp = client.get(
        f"/auth/login?rd={TRANSFER_RD}",
        cookies={"bastion_session": token},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers.get("location") == "/apps"


def test_login_injected_user_without_subdomain_cookie_goes_to_apps(
    client: TestClient, db_session: Session
):
    """auth_request identity alone must not bounce to transfer (401 loop)."""
    settings = _native_settings()
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings
    _enable_native_realm(db_session)

    fake_user = UserContext(
        email="alice@example.com",
        username="alice",
        groups=["ARSYSTEMS-Users"],
        realm_slug="ar-systems",
        auth_source="sso",
        is_admin=False,
        keycloak_user_id="kc-sub",
    )
    with patch("app.web.pages.get_user_context", return_value=fake_user):
        resp = client.get(
            f"/login?rd={TRANSFER_RD}",
            follow_redirects=False,
        )

    assert resp.status_code == 302
    assert resp.headers.get("location") == "/apps"


def test_login_invalid_native_cookie_with_absolute_rd_shows_login_not_loop(
    client: TestClient, db_session: Session
):
    settings = _native_settings()
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings
    _enable_native_realm(db_session)

    resp = client.get(
        f"/auth/login?rd={TRANSFER_RD}",
        cookies={"bastion_session": "not-a-jwt"},
        follow_redirects=False,
    )
    # Must not 302 back to transfer; either login HTML or /apps.
    loc = resp.headers.get("location") or ""
    assert TRANSFER_RD not in loc
    if resp.status_code == 302:
        assert loc.startswith("/")
    else:
        assert resp.status_code == 200
        assert "connexion" in resp.text.lower() or "login" in resp.text.lower()
