"""Break-glass must survive an outage of the hot store it writes to.

Session rows, binding anchors, rate events and audit logs are all hot tables.
When PostgreSQL refuses connections, refusing the login too would strand the
one account able to repair it — which is what happened on 2026-08-15 after the
postgres role password drifted from the one the application had stored.
"""

from unittest.mock import patch

import jwt
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.breakglass import (
    COOKIE_MAX_AGE,
    DEGRADED_TOKEN_TTL_SEC,
    issue_breakglass_token,
)
from app.breakglass_store import set_breakglass_password
from app.models import BreakGlassSession

PASSWORD = "correct-password-12"
PG_DOWN = OperationalError(
    "connect", {}, Exception('password authentication failed for user "bastion_hot"')
)


def _login(client: TestClient) -> object:
    return client.post(
        "/auth/breakglass",
        data={"username": "admin", "password": PASSWORD, "rd": "/dashboard"},
        headers={"X-Real-IP": "10.0.0.8"},
        follow_redirects=False,
    )


def test_login_succeeds_when_the_session_registry_is_down(
    client: TestClient, db_session: Session
):
    set_breakglass_password(db_session, "admin", PASSWORD)

    with patch(
        "app.breakglass.register_breakglass_session", side_effect=PG_DOWN
    ):
        response = _login(client)

    assert response.status_code == 302, "a hot store outage must not yield a 500"
    assert response.headers["location"] == "/dashboard"
    assert "bg_session" in response.cookies


def test_login_succeeds_in_production_after_lazy_secret_ensure(
    client: TestClient, db_session: Session, monkeypatch
):
    """Production without env BREAKGLASS_JWT_SECRET must seed from SQLite, not 500."""
    from cryptography.fernet import Fernet

    from app.runtime_secrets_service import reset_runtime_secrets_cache_for_tests
    from app.sso_settings import Settings, get_settings

    set_breakglass_password(db_session, "admin", PASSWORD)
    reset_runtime_secrets_cache_for_tests()
    key = Fernet.generate_key().decode()
    settings = Settings(
        environment="production",
        breakglass_jwt_secret="",
        session_hop_secret="",
        vault_portal_internal_token="vault-only",
        portal_secret_encryption_key=key,
        vault_portal_vault_fernet_key=key,
        portal_domain="portal.test",
        database_url="sqlite://",
    )
    monkeypatch.setattr("app.web.pages.get_settings", lambda: settings)
    get_settings.cache_clear()

    response = _login(client)
    assert response.status_code == 302, response.text[:500]
    assert response.headers["location"] == "/dashboard"
    assert "bg_session" in response.cookies


def test_login_shows_form_not_500_when_token_issue_fails(
    client: TestClient, db_session: Session
):
    set_breakglass_password(db_session, "admin", PASSWORD)

    with patch(
        "app.web.pages.issue_breakglass_token",
        side_effect=RuntimeError("BREAKGLASS_JWT_SECRET is required in production"),
    ):
        response = _login(client)

    assert response.status_code == 200
    assert (
        "BREAKGLASS_JWT_SECRET" in response.text
        or "session break-glass" in response.text.lower()
    )


def test_unregistered_token_is_short_lived(client: TestClient, db_session: Session):
    """It cannot be revoked, so the window it opens has to be bounded."""
    set_breakglass_password(db_session, "admin", PASSWORD)

    with patch("app.breakglass.register_breakglass_session", side_effect=PG_DOWN):
        token, _jti = issue_breakglass_token(db_session, "admin", "s3cret-signing-key")

    payload = jwt.decode(
        token,
        "s3cret-signing-key",
        algorithms=["HS256"],
        options={"verify_aud": False},
    )
    lifetime = payload["exp"] - payload["iat"]
    assert lifetime == DEGRADED_TOKEN_TTL_SEC
    assert lifetime < COOKIE_MAX_AGE


def test_nominal_token_keeps_the_full_lifetime(
    client: TestClient, db_session: Session
):
    set_breakglass_password(db_session, "admin", PASSWORD)

    token, jti = issue_breakglass_token(db_session, "admin", "s3cret-signing-key")

    payload = jwt.decode(
        token,
        "s3cret-signing-key",
        algorithms=["HS256"],
        options={"verify_aud": False},
    )
    assert payload["exp"] - payload["iat"] == COOKIE_MAX_AGE
    assert db_session.query(BreakGlassSession).filter_by(jti=jti).first() is not None


def test_an_established_session_survives_the_outage(
    client: TestClient, db_session: Session
):
    """The registry is consulted on every protected request, not just at login.

    Without this, the admin logs in fine and then every page 500s.
    """
    set_breakglass_password(db_session, "admin", PASSWORD)
    token = _login(client).cookies.get("bg_session")
    assert token

    real_query = Session.query

    def registry_is_down(self, *entities, **kwargs):
        if entities and entities[0] is BreakGlassSession:
            raise PG_DOWN
        return real_query(self, *entities, **kwargs)

    with patch.object(Session, "query", registry_is_down):
        page = client.get(
            "/dashboard",
            cookies={"bg_session": token},
            headers={"X-Real-IP": "10.0.0.8"},
            follow_redirects=False,
        )

    assert page.status_code != 500, "an outage must not log the admin out with a 500"


def test_failed_login_does_not_500_when_rate_events_are_down(
    client: TestClient, db_session: Session
):
    set_breakglass_password(db_session, "admin", PASSWORD)

    with patch(
        "app.security.banning.engine._prune_and_count", side_effect=PG_DOWN
    ):
        response = client.post(
            "/auth/breakglass",
            data={"username": "admin", "password": "wrong", "rd": "/dashboard"},
            headers={"X-Real-IP": "10.0.0.8"},
            follow_redirects=False,
        )

    assert response.status_code == 200
    assert "Identifiants invalides" in response.text
