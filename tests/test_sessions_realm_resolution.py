"""Realm resolution for portal sessions (native OIDC JWT vs default fallback)."""

from __future__ import annotations

from starlette.requests import Request

from app.models import ActiveSession, utcnow
from app.oidc_bff import issue_oidc_session, validate_oidc_session_cookie
from app.sso_settings import Settings
from app.web.sessions_service import (
    KIND_USER,
    _portal_session_id,
    _touch_portal_session,
)
from app.web.user_context import UserContext, _resolve_portal_realm_slug

OIDC_SECRET = "oidc-session-hmac-key-32bytes-min!!"


def _settings(**kwargs) -> Settings:
    base = dict(
        environment="test",
        database_url="sqlite://",
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        sso_portal_default_realm_slug="ar-systems",
        oidc_session_cookie_name="bastion_session",
        oidc_session_max_age=3600,
        oidc_session_jwt_secret=OIDC_SECRET,
    )
    base.update(kwargs)
    return Settings(**base)


def test_resolve_realm_ignores_empty_header_uses_default():
    req = Request({"type": "http", "headers": [(b"x-portal-realm-slug", b"")]})
    assert _resolve_portal_realm_slug(req, _settings(), db=None) == "ar-systems"


def test_resolve_realm_prefers_nonempty_header():
    req = Request({"type": "http", "headers": [(b"x-portal-realm-slug", b"clients")]})
    assert _resolve_portal_realm_slug(req, _settings(), db=None) == "clients"


def test_resolve_realm_from_bastion_session_jwt(db_session):
    settings = _settings()
    token, _jti = issue_oidc_session(
        db_session,
        sub="sub-daniel",
        username="daniel.guerive",
        realm="clients",
        secret=OIDC_SECRET,
        max_age=3600,
        groups=[],
        email="daniel.guerive@apisystems.com",
    )
    db_session.commit()
    assert validate_oidc_session_cookie(token, db=db_session, settings=settings)
    req = Request(
        {
            "type": "http",
            "headers": [
                (b"cookie", f"bastion_session={token}".encode()),
                (b"x-portal-realm-slug", b""),
            ],
        }
    )
    assert _resolve_portal_realm_slug(req, settings, db_session) == "clients"


def test_touch_portal_drops_misattributed_default_realm(db_session):
    email = "daniel.guerive@apisystems.com"
    wrong_id = _portal_session_id(email, "ar-systems")
    now = utcnow()
    db_session.add(
        ActiveSession(
            id=wrong_id,
            kind=KIND_USER,
            user_email=email,
            username="daniel.guerive",
            realm="ar-systems",
            protocol="OIDC",
            target="portal",
            status="active",
            started_at=now,
            last_seen_at=now,
        )
    )
    db_session.commit()

    user = UserContext(
        email=email,
        username="daniel.guerive",
        groups=[],
        realm_slug="clients",
        auth_source="sso",
        is_admin=False,
    )
    row = _touch_portal_session(db_session, user, "203.0.113.10")
    db_session.commit()
    assert row.realm == "clients"
    assert row.id == _portal_session_id(email, "clients")
    assert db_session.query(ActiveSession).filter_by(id=wrong_id).first() is None
