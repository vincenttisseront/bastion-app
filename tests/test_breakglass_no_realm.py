"""Break-glass identities must not be stamped with an SSO realm or pending queue."""

from __future__ import annotations

from unittest.mock import MagicMock

from sqlalchemy.orm import Session

from app.breakglass import COOKIE_NAME, issue_breakglass_token
from app.models import ActiveSession, PendingUser
from app.sso_settings import Settings
from app.web.sessions_service import touch_portal_session
from app.web.user_context import UserContext, get_user_context, is_breakglass_email


SECRET = "test-breakglass-secret-for-pytest-32b"


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
        breakglass_jwt_secret=SECRET,
        sso_portal_default_realm_slug="ar-systems",
        portal_admin_groups=["portal-admins"],
    )


def test_is_breakglass_email():
    assert is_breakglass_email("admin@breakglass.local")
    assert is_breakglass_email("Admin@Breakglass.Local")
    assert not is_breakglass_email("admin@ar-systems.fr")
    assert not is_breakglass_email(None)


def test_get_user_context_breakglass_has_empty_realm(db_session: Session):
    settings = _settings()
    token, _jti = issue_breakglass_token(db_session, "admin", SECRET)
    db_session.commit()

    request = MagicMock()
    request.headers = {}
    request.cookies = {COOKIE_NAME: token}

    user = get_user_context(request, settings=settings, db=db_session)
    assert user is not None
    assert user.is_breakglass
    assert user.email == "admin@breakglass.local"
    assert user.realm_slug == ""


def test_get_user_context_breakglass_header_clears_default_realm():
    settings = _settings()
    request = MagicMock()
    request.headers = {
        "X-Email": "admin@breakglass.local",
        "X-Preferred-Username": "admin",
        "X-Portal-Auth-Source": "breakglass",
        "X-Portal-Realm-Slug": "ar-systems",
        "X-Groups": "portal-admins",
    }
    request.cookies = {}

    user = get_user_context(request, settings=settings, db=None)
    assert user is not None
    assert user.is_breakglass
    assert user.realm_slug == ""


def test_touch_portal_session_breakglass_no_realm_no_pending(db_session: Session):
    user = UserContext(
        email="admin@breakglass.local",
        username="admin",
        groups=["portal-admins"],
        realm_slug="",
        auth_source="breakglass",
        is_admin=True,
    )
    # Legacy wrongly-attributed row (pre-fix production state)
    db_session.add(
        ActiveSession(
            id="portal:admin@breakglass.local:ar-systems",
            kind="user",
            user_email="admin@breakglass.local",
            username="admin",
            realm="ar-systems",
            protocol="BREAKGLASS",
            target="portal",
            status="active",
        )
    )
    db_session.commit()

    row = touch_portal_session(db_session, user, "10.0.0.8")
    assert row is not None
    assert row.realm == ""
    assert row.id == "portal:admin@breakglass.local:"
    assert row.protocol == "BREAKGLASS"
    assert (
        db_session.query(ActiveSession)
        .filter_by(id="portal:admin@breakglass.local:ar-systems")
        .first()
        is None
    )
    assert db_session.query(PendingUser).count() == 0
