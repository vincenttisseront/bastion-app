"""identite_utilisateur — password kept for the portal session (opt-in per app)."""

from __future__ import annotations

import logging
from datetime import timedelta
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.admin.app_delete import purge_application
from app.admin.throttling import reset_test_rate_limits
from app.auth.oidc_bff import revoke_oidc_sessions_for_identity
from app.bastion.drivers.base import RoboticLoginError
from app.bastion.drivers.crushftp import CrushFTPSession
from app.models import App, AuditLog, IdentityPasswordCache, utcnow
from app.rbac.grants_service import AccessGrantCreate, create_grant
from app.robotic import identity_password_cache as cache
from app.sso_settings import Settings

SECRET_PASSWORD = "CachedIdentityPass-MustNotLeak-4fQ"
NEW_PASSWORD = "NewIdentityPass-MustNotLeak-8wR"
KC_USER = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff0002"
FULL_EMAIL = "alice.martin@example.com"
OPEN_URL = "/api/apps/grommunio/open-with-identity"

USER_HEADERS = {
    "X-Email": FULL_EMAIL,
    "X-Preferred-Username": "alice.martin",
    "X-Groups": "mail-users",
    "X-User-Id": KC_USER,
}
HTML = {**USER_HEADERS, "Accept": "text/html"}


@pytest.fixture(autouse=True)
def _reset_throttle():
    reset_test_rate_limits()
    yield
    reset_test_rate_limits()


def _settings(**kwargs) -> Settings:
    defaults = {
        "vault_portal_internal_token": "test-secret",
        "portal_secret_encryption_key": "test-encryption-key-for-pytest-only",
        "database_url": "sqlite://",
    }
    defaults.update(kwargs)
    return Settings(**defaults)


def _seed_app(db: Session, *, cache_enabled: bool = True, **kwargs) -> App:
    values = {
        "slug": "grommunio",
        "label": "Grommunio",
        "upstream_url": "https://mail.example/",
        "robotic_driver": "crushftp",
        "access_mode": "legacy_path_proxy",
        "credential_mode": "identite_utilisateur",
        "identity_password_session_cache": cache_enabled,
        "enabled": True,
    }
    values.update(kwargs)
    app = App(**values)
    db.add(app)
    db.commit()
    db.refresh(app)
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


class _Upstream:
    """CrushFTP driver double that records the passwords it received."""

    def __init__(self, *, accept: set[str]):
        self.accept = accept
        self.seen: list[str] = []

    async def login(self, _driver, _base_url, _username, password, *args, **kwargs):
        self.seen.append(password)
        if password not in self.accept:
            raise RoboticLoginError("rejected")
        return CrushFTPSession(
            cookies={"CrushAuth": "OKCOOKIE", "currentAuth": "OK"},
            base_url="https://mail.example/",
        )

    def patches(self):
        upstream = self

        async def _login(driver_self, *args, **kwargs):
            return await upstream.login(driver_self, *args, **kwargs)

        return (
            patch("app.robotic.impersonate_service.CrushFTPDriver.login", new=_login),
            patch(
                "app.robotic.impersonate_service.CrushFTPDriver.get_username",
                new=AsyncMock(return_value=FULL_EMAIL),
            ),
            patch("app.robotic.impersonate_service.CrushFTPDriver.logout", new=AsyncMock()),
        )


def _open(client: TestClient, upstream: _Upstream, data: dict):
    p1, p2, p3 = upstream.patches()
    with p1, p2, p3:
        return client.post(OPEN_URL, headers=HTML, data=data, follow_redirects=False)


def _cache_set_cookie(resp) -> str | None:
    for header in resp.headers.get_list("set-cookie"):
        if header.startswith(f"{cache.COOKIE_NAME}="):
            return header
    return None


def _rows(db: Session) -> list[IdentityPasswordCache]:
    db.expire_all()
    return db.query(IdentityPasswordCache).all()


# --- service ---------------------------------------------------------------


def _remember(db: Session, app: App, settings: Settings, **kwargs):
    params = {
        "cookie": None,
        "app": app,
        "user_key": KC_USER,
        "user_email": FULL_EMAIL,
        "login_username": FULL_EMAIL,
        "password": SECRET_PASSWORD,
    }
    params.update(kwargs)
    return cache.remember_password(db, settings, **params)


def test_roundtrip_and_ciphertext_hides_password(db_session: Session):
    app = _seed_app(db_session)
    settings = _settings()
    cookie = _remember(db_session, app, settings)

    row = _rows(db_session)[0]
    assert SECRET_PASSWORD not in row.ciphertext
    assert cookie.handle == row.handle
    # The key half never reaches the database.
    assert cookie.value().split(".", 1)[1] not in row.ciphertext

    got = cache.recall_password(
        db_session,
        settings,
        cookie=cache.parse_cookie(cookie.value()),
        app=app,
        user_key=KC_USER,
        login_username=FULL_EMAIL,
    )
    assert got == SECRET_PASSWORD
    assert _rows(db_session)[0].last_used_at is not None


def test_database_row_alone_cannot_decrypt(db_session: Session):
    """Same handle, other key half (e.g. forged cookie) → nothing, row dropped."""
    app = _seed_app(db_session)
    settings = _settings()
    cookie = _remember(db_session, app, settings)
    forged = cache.CacheCookie(handle=cookie.handle, secret=b"\x00" * 32)

    got = cache.recall_password(
        db_session, settings, cookie=forged, app=app,
        user_key=KC_USER, login_username=FULL_EMAIL,
    )
    assert got is None
    assert _rows(db_session) == []


def test_other_signing_secret_cannot_decrypt(db_session: Session):
    app = _seed_app(db_session)
    cookie = _remember(db_session, app, _settings())
    got = cache.recall_password(
        db_session,
        _settings(portal_signing_secret="another-server-secret"),
        cookie=cookie,
        app=app,
        user_key=KC_USER,
        login_username=FULL_EMAIL,
    )
    assert got is None


@pytest.mark.parametrize(
    "user_key,login",
    [("someone-else", FULL_EMAIL), (KC_USER, "bob@example.com")],
)
def test_bound_to_identity(db_session: Session, user_key: str, login: str):
    app = _seed_app(db_session)
    settings = _settings()
    cookie = _remember(db_session, app, settings)
    got = cache.recall_password(
        db_session, settings, cookie=cookie, app=app,
        user_key=user_key, login_username=login,
    )
    assert got is None
    assert _rows(db_session) == []


def test_expired_row_is_dropped(db_session: Session):
    app = _seed_app(db_session)
    settings = _settings()
    cookie = _remember(db_session, app, settings, now=utcnow() - timedelta(hours=11))
    got = cache.recall_password(
        db_session, settings, cookie=cookie, app=app,
        user_key=KC_USER, login_username=FULL_EMAIL,
    )
    assert got is None
    assert _rows(db_session) == []


def test_ttl_never_exceeds_portal_session():
    assert cache.ttl_seconds(_settings()) == 10 * 3600
    assert (
        cache.ttl_seconds(_settings(identity_password_cache_ttl=48 * 3600, oidc_session_max_age=3600))
        == 3600
    )
    assert cache.ttl_seconds(_settings(identity_password_cache_ttl=1)) == 300


@pytest.mark.parametrize(
    "raw",
    ["", "nodot", "a.b", "x" * 32 + "." + "!" * 43, "x" * 31 + "." + "A" * 43],
)
def test_parse_cookie_rejects_garbage(raw: str):
    assert cache.parse_cookie(raw) is None


def test_parse_cookie_roundtrip():
    cookie = cache.new_cookie()
    assert cache.parse_cookie(cookie.value()) == cookie


def test_admin_disconnect_drops_identity_rows(db_session: Session):
    app = _seed_app(db_session)
    settings = _settings()
    _remember(db_session, app, settings)
    _remember(db_session, app, settings, user_key="other-sub", user_email="bob@example.com")

    revoke_oidc_sessions_for_identity(
        db_session,
        realm_slug=None,
        emails={FULL_EMAIL},
        keycloak_subs={KC_USER},
        revoked_by="admin",
    )
    db_session.commit()
    remaining = _rows(db_session)
    assert [r.user_key for r in remaining] == ["other-sub"]


def test_app_purge_and_opt_out_drop_rows(db_session: Session):
    app = _seed_app(db_session)
    settings = _settings()
    _remember(db_session, app, settings)

    app.identity_password_session_cache = False
    assert cache.forget_if_disabled(db_session, app) == 1
    db_session.commit()
    assert _rows(db_session) == []

    app.identity_password_session_cache = True
    _remember(db_session, app, settings)
    summary = purge_application(db_session, app)
    db_session.commit()
    assert summary["identity_password_cache"] == 1
    assert _rows(db_session) == []


def test_disabled_unless_identity_mode(db_session: Session):
    app = _seed_app(db_session, credential_mode="shared")
    assert cache.is_enabled_for(app) is False


# --- HTTP flow ---------------------------------------------------------------


def test_remember_then_open_without_prompt(client: TestClient, db_session: Session):
    _seed_app(db_session)
    upstream = _Upstream(accept={SECRET_PASSWORD})

    first = _open(client, upstream, {"password": SECRET_PASSWORD, "remember": "1"})
    assert first.status_code == 303
    assert first.headers["location"] == "/proxy/grommunio/"
    set_cookie = _cache_set_cookie(first)
    assert set_cookie is not None
    lowered = set_cookie.lower()
    assert "httponly" in lowered and "secure" in lowered and "samesite=strict" in lowered
    assert "domain=" not in lowered  # host-only: never sent to app subdomains
    assert SECRET_PASSWORD not in set_cookie
    assert len(_rows(db_session)) == 1

    second = _open(client, upstream, {"use_cached": "1"})
    assert second.status_code == 303
    assert second.headers["location"] == "/proxy/grommunio/"
    assert upstream.seen == [SECRET_PASSWORD, SECRET_PASSWORD]


def test_cache_disabled_app_ignores_remember(client: TestClient, db_session: Session):
    _seed_app(db_session, cache_enabled=False)
    upstream = _Upstream(accept={SECRET_PASSWORD})
    resp = _open(client, upstream, {"password": SECRET_PASSWORD, "remember": "1"})
    assert resp.status_code == 303
    assert _cache_set_cookie(resp) is None
    assert _rows(db_session) == []


def test_unchecked_remember_drops_previous_cache(client: TestClient, db_session: Session):
    _seed_app(db_session)
    upstream = _Upstream(accept={SECRET_PASSWORD})
    _open(client, upstream, {"password": SECRET_PASSWORD, "remember": "1"})
    assert len(_rows(db_session)) == 1

    _open(client, upstream, {"password": SECRET_PASSWORD})
    assert _rows(db_session) == []


def test_use_cached_without_cache_reprompts(client: TestClient, db_session: Session):
    _seed_app(db_session)
    upstream = _Upstream(accept={SECRET_PASSWORD})
    resp = _open(client, upstream, {"use_cached": "1"})
    assert resp.status_code == 303
    loc = urlparse(resp.headers["location"])
    assert loc.path == "/apps"
    assert parse_qs(loc.query) == {
        "identity_prompt": ["grommunio"],
        "identity_reason": ["expired"],
    }
    assert upstream.seen == []


def test_changed_password_drops_cache_and_reprompts(
    client: TestClient, db_session: Session, caplog
):
    _seed_app(db_session)
    _open(client, _Upstream(accept={SECRET_PASSWORD}), {"password": SECRET_PASSWORD, "remember": "1"})

    # AD password changed since: the cached one is now refused upstream.
    changed = _Upstream(accept={NEW_PASSWORD})
    with caplog.at_level(logging.DEBUG):
        resp = _open(client, changed, {"use_cached": "1"})
    assert resp.status_code == 303
    loc = urlparse(resp.headers["location"])
    assert loc.path == "/apps"
    assert parse_qs(loc.query)["identity_reason"] == ["rejected"]
    assert _rows(db_session) == []
    assert SECRET_PASSWORD not in caplog.text

    audits = db_session.query(AuditLog).all()
    assert all(SECRET_PASSWORD not in str(a.details) for a in audits)


def test_logout_drops_cache_and_cookie(client: TestClient, db_session: Session):
    _seed_app(db_session)
    _open(client, _Upstream(accept={SECRET_PASSWORD}), {"password": SECRET_PASSWORD, "remember": "1"})
    assert len(_rows(db_session)) == 1

    resp = client.get("/logout", headers=USER_HEADERS, follow_redirects=False)
    assert resp.status_code == 302
    cleared = _cache_set_cookie(resp)
    assert cleared is not None and ("max-age=0" in cleared.lower() or "expires=" in cleared.lower())
    assert _rows(db_session) == []


def test_catalogue_marks_cached_tile(client: TestClient, db_session: Session):
    _seed_app(db_session)
    before = client.get("/apps", headers=USER_HEADERS)
    assert 'data-identity-cache="1"' in before.text
    assert 'data-identity-cached="1"' not in before.text

    _open(client, _Upstream(accept={SECRET_PASSWORD}), {"password": SECRET_PASSWORD, "remember": "1"})
    after = client.get("/apps", headers=USER_HEADERS)
    assert 'data-identity-cached="1"' in after.text
    assert "resumeIdentityPrompt" in after.text
    assert SECRET_PASSWORD not in after.text
