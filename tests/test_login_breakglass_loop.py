"""Regression: stale bg_session must not redirect-loop login ↔ /apps."""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.breakglass import COOKIE_NAME, BreakglassAuthResult
from app.breakglass_store import set_breakglass_password
from app.web.user_context import UserContext
from tests.test_auth_login_flow import _add_default_idp


def test_login_clears_invalid_breakglass_instead_of_redirect_loop(
    client: TestClient, db_session: Session
):
    _add_default_idp(db_session)
    set_breakglass_password(db_session, "admin", "super-secret-password")

    fake_user = UserContext(
        email="admin@breakglass.local",
        username="admin",
        groups=["portal-admins"],
        realm_slug="ar-systems",
        auth_source="breakglass",
        is_admin=True,
    )

    with (
        patch("app.web.pages.get_user_context", return_value=fake_user),
        patch(
            "app.web.pages.process_breakglass_auth_request",
            return_value=BreakglassAuthResult(ok=False),
        ),
    ):
        resp = client.get(
            "/auth/login?rd=/apps",
            cookies={COOKIE_NAME: "stale-token"},
            follow_redirects=False,
        )

    assert resp.status_code == 200
    assert not (resp.headers.get("location") or "")
    assert "break-glass" in resp.text.lower() or "connexion" in resp.text.lower()
    sc = (resp.headers.get("set-cookie") or "").lower()
    assert "bg_session" in sc
