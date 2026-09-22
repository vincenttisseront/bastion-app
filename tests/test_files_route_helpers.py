"""Coverage for files route helpers on the Sonar new-code period."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.files import routes as files_routes
from app.web.user_context import UserContext


def _user(**extra) -> UserContext:
    base = dict(
        email="user@example.com",
        username="user",
        groups=[],
        realm_slug="default",
        auth_source="sso",
        is_admin=False,
        keycloak_user_id="kc-1",
    )
    base.update(extra)
    return UserContext(**base)


def test_actor_prefers_email_then_username():
    assert files_routes._actor(_user()) == "user@example.com"
    assert (
        files_routes._actor(
            _user(email="", username="", keycloak_user_id="kc-9")
        )
        == "kc-9"
    )


def test_portal_admin_short_circuits(monkeypatch):
    assert files_routes._portal_admin(_user(is_admin=True), MagicMock(), MagicMock()) is True
    assert (
        files_routes._portal_admin(
            _user(auth_source="breakglass"), MagicMock(), MagicMock()
        )
        is True
    )

    called = {"n": 0}

    def resolve(*_a, **_k):
        called["n"] += 1
        return False

    monkeypatch.setattr("app.web.portal._resolve_portal_admin", resolve)
    assert files_routes._portal_admin(_user(), MagicMock(), MagicMock()) is False
    assert called["n"] == 1
