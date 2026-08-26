"""Point 5 — /sessions kind=user enrichment (OIDC vs BREAKGLASS, SSO logout badge)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import respx
from sqlalchemy.orm import Session

from app.models import ActiveSession, RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings
from app.web.sessions_service import (
    SSO_LOGOUT_RESIDUAL_WINDOW,
    _sso_logout_badge,
    build_session_groups,
    get_active_sessions,
    mark_sso_logout_requested,
)

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
    "X-Portal-Realm-Slug": "ar-systems",
}


def _test_settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )


def _make_realm(db: Session, settings: Settings) -> RealmConfig:
    realm = RealmConfig(
        slug="kc",
        name="Keycloak",
        issuer_url="https://kc.example.com/realms/demo",
        client_id="login-client",
        client_secret_encrypted=encrypt_secret("login-secret", settings),
        redirect_uri=f"https://{settings.portal_domain}/oauth2/kc/callback",
        scopes="openid profile email",
        oauth2_proxy_port=4181,
        is_default=False,
        enabled=False,
        keycloak_admin_client_id="bastion-admin-sync",
        keycloak_admin_client_secret_encrypted=encrypt_secret("admin-secret", settings),
        groups_sync_enabled=True,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def _portal_row(
    db: Session,
    *,
    sid: str,
    email: str,
    username: str,
    protocol: str = "OIDC",
    details: dict | None = None,
) -> ActiveSession:
    now = datetime.now(timezone.utc)
    row = ActiveSession(
        id=sid,
        kind="user",
        user_email=email,
        username=username,
        realm="demo",
        protocol=protocol,
        target="portal",
        status="active",
        started_at=now - timedelta(minutes=30),
        last_seen_at=now,
        details=details or {},
    )
    db.add(row)
    db.commit()
    return row


def test_oidc_and_breakglass_distinct_actions_in_api(client, db_session: Session):
    _portal_row(
        db_session,
        sid="oidc-1",
        email="alice@example.com",
        username="alice",
        protocol="OIDC",
    )
    _portal_row(
        db_session,
        sid="bg-1",
        email="bg-admin@local",
        username="bg-admin",
        protocol="BREAKGLASS",
        details={"jti": "jti-abc-12345678"},
    )

    api = client.get("/api/sessions?kind=user", headers=ADMIN_HEADERS).json()
    by_id = {s["id"]: s for s in api["sessions"]}
    oidc = by_id["oidc-1"]
    bg = by_id["bg-1"]

    assert oidc["auth_family"] == "oidc"
    assert oidc["type_label"] == "Portail OIDC"
    assert oidc["live_status"] == "declarative"
    assert oidc["live_status_label"] == "REGISTRE"
    assert oidc["verifiable"] is False
    assert oidc["freshness"]["mode"] == "declarative"
    assert "cookie_refresh" in oidc["freshness"]["policy_label"]
    assert oidc["can_rotate"] is False
    assert oidc["can_revoke"] is True

    assert bg["auth_family"] == "breakglass"
    assert bg["type_label"] == "Break-glass"
    assert bg["jti"] == "jti-abc-12345678"
    assert bg["live_status_label"] == "REGISTRE"
    assert bg["can_rotate"] is False
    assert "jti" in bg["action_titles"]["revoke"].lower() or "break-glass" in bg[
        "action_titles"
    ]["revoke"].lower()

    groups = {g["user_email"]: g for g in api["groups"]}
    assert groups["alice@example.com"]["show_disconnect"] is True
    assert groups["alice@example.com"]["has_oidc"] is True
    assert groups["bg-admin@local"]["show_disconnect"] is False
    assert groups["bg-admin@local"]["has_breakglass"] is True


def test_sessions_page_includes_user_filter_and_family_chips(client, db_session: Session):
    _portal_row(
        db_session,
        sid="oidc-1",
        email="alice@example.com",
        username="alice",
    )
    page = client.get("/sessions?kind=user", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    html = page.text
    assert 'id="sessions-user-filter"' in html
    assert "sessions-family-oidc" in html or "OIDC" in html
    assert "bastion-sessions.js" in html


def test_sso_logout_badge_after_revoke_sso(client, db_session: Session):
    """revoke-sso drops portal registry rows; badge is no longer needed on the card."""
    settings = _test_settings()
    realm = _make_realm(db_session, settings)
    _portal_row(
        db_session,
        sid="oidc-alice",
        email="alice@example.com",
        username="alice",
    )

    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    user_url = "https://kc.example.com/admin/realms/demo/users/kc-alice"
    logout_url = "https://kc.example.com/admin/realms/demo/users/kc-alice/logout"

    with respx.mock:
        respx.post(token_url).respond(
            200,
            json={"access_token": "t"},
            headers={"content-type": "application/json"},
        )
        respx.get(user_url).respond(
            200,
            json={
                "id": "kc-alice",
                "username": "alice",
                "email": "alice@example.com",
            },
        )
        respx.post(logout_url).respond(204)

        resp = client.post(
            f"/admin/users/kc-alice/sessions/revoke-sso?realm_id={realm.id}",
            headers={**ADMIN_HEADERS, "accept": "application/json"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body.get("portal_rows_removed", 0) >= 1

    api = client.get("/api/sessions?kind=user", headers=ADMIN_HEADERS).json()
    emails = {g["user_email"] for g in api["groups"]}
    assert "alice@example.com" not in emails
    assert (
        db_session.query(ActiveSession).filter_by(id="oidc-alice").first() is None
    )


def test_sso_logout_badge_expires_after_residual_window(db_session: Session):
    now = datetime.now(timezone.utc)
    fresh = _sso_logout_badge(now - timedelta(minutes=10), now=now)
    assert fresh is not None
    assert "Déconnexion demandée" in fresh["label"]

    expired = _sso_logout_badge(
        now - SSO_LOGOUT_RESIDUAL_WINDOW - timedelta(minutes=1), now=now
    )
    assert expired is None

    _portal_row(
        db_session,
        sid="oidc-old",
        email="old@example.com",
        username="old",
        details={
            "sso_logout_requested_at": (
                now - SSO_LOGOUT_RESIDUAL_WINDOW - timedelta(minutes=5)
            ).isoformat(),
        },
    )
    sessions = get_active_sessions(db_session)
    groups = build_session_groups(db_session, sessions)
    old = next(g for g in groups if g["user_email"] == "old@example.com")
    assert old["sso_logout"] is None


def test_mark_sso_logout_skips_breakglass(db_session: Session):
    _portal_row(
        db_session,
        sid="bg-only",
        email="bg@local",
        username="bg",
        protocol="BREAKGLASS",
        details={"jti": "jti-x"},
    )
    n = mark_sso_logout_requested(
        db_session, emails={"bg@local"}, usernames={"bg"}, actor="admin"
    )
    assert n == 0
    row = db_session.query(ActiveSession).filter_by(id="bg-only").one()
    assert "sso_logout_requested_at" not in (row.details or {})
