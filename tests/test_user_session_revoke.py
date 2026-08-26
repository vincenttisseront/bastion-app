"""Tests — revoke-all app sessions + Keycloak Admin logout."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import respx
from sqlalchemy.orm import Session

from app.models import ActiveSession, AuditLog, RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings
from app.web.sessions_service import revoke_active_session

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


def _make_realm(db: Session, settings: Settings, **kwargs) -> RealmConfig:
    realm = RealmConfig(
        slug=kwargs.get("slug", "kc"),
        name=kwargs.get("name", "Keycloak"),
        issuer_url=kwargs.get("issuer_url", "https://kc.example.com/realms/demo"),
        client_id="login-client",
        client_secret_encrypted=encrypt_secret("login-secret", settings),
        redirect_uri=f"https://{settings.portal_domain}/oauth2/kc/callback",
        scopes="openid profile email",
        oauth2_proxy_port=4181,
        is_default=False,
        enabled=False,
        keycloak_admin_client_id=kwargs.get("admin_client_id", "bastion-admin-sync"),
        keycloak_admin_client_secret_encrypted=encrypt_secret("admin-secret", settings),
        groups_sync_enabled=True,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def _app_session(
    db: Session,
    *,
    sid: str,
    email: str = "alice@example.com",
    username: str = "alice",
    target: str = "wiki",
) -> ActiveSession:
    now = datetime.now(timezone.utc)
    row = ActiveSession(
        id=sid,
        kind="app",
        user_email=email,
        username=username,
        realm="demo",
        protocol="HTTPS",
        target=target,
        status="active",
        started_at=now,
        last_seen_at=now,
        details={"session_cookies": {"CrushAuth": "x"}},
    )
    db.add(row)
    db.commit()
    return row


def test_revoke_all_three_app_sessions(client, db_session: Session):
    _app_session(db_session, sid="s1", target="wiki")
    _app_session(db_session, sid="s2", target="mail")
    _app_session(db_session, sid="s3", target="crm")
    # portal kind=user must not be touched
    now = datetime.now(timezone.utc)
    db_session.add(
        ActiveSession(
            id="portal-alice",
            kind="user",
            user_email="alice@example.com",
            username="alice",
            realm="demo",
            protocol="OIDC",
            target="portal",
            status="active",
            started_at=now,
            last_seen_at=now,
        )
    )
    db_session.commit()

    resp = client.post(
        "/admin/users/alice@example.com/sessions/revoke-all",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["revoked_count"] == 3
    assert body["failed_count"] == 0
    assert {r["session_id"] for r in body["revoked"]} == {"s1", "s2", "s3"}

    remaining = db_session.query(ActiveSession).all()
    assert len(remaining) == 1
    assert remaining[0].id == "portal-alice"

    audits = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "sessions.revoke_all_app")
        .all()
    )
    assert len(audits) == 1
    assert audits[0].details["revoked_count"] == 3


def test_revoke_all_continues_on_partial_failure(client, db_session: Session):
    _app_session(db_session, sid="ok1", target="wiki")
    _app_session(db_session, sid="bad", target="mail")
    _app_session(db_session, sid="ok2", target="crm")

    real_revoke = revoke_active_session

    def flaky_revoke(db, session, **kwargs):
        if session.id == "bad":
            raise RuntimeError("app cible down / cookie absent")
        return real_revoke(db, session, **kwargs)

    with patch(
        "app.web.sessions_service.revoke_active_session",
        side_effect=flaky_revoke,
    ):
        resp = client.post(
            "/admin/users/alice@example.com/sessions/revoke-all",
            headers={**ADMIN_HEADERS, "accept": "application/json"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["revoked_count"] == 2
    assert body["failed_count"] == 1
    assert body["failed"][0]["session_id"] == "bad"
    assert "app cible down" in body["failed"][0]["error"]

    ids = {r.id for r in db_session.query(ActiveSession).all()}
    assert "bad" in ids
    assert "ok1" not in ids
    assert "ok2" not in ids


@respx.mock
def test_keycloak_logout_missing_manage_users_role(client, db_session: Session):
    settings = _test_settings()
    realm = _make_realm(db_session, settings)

    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    user_url = "https://kc.example.com/admin/realms/demo/users/kc-alice"
    logout_url = "https://kc.example.com/admin/realms/demo/users/kc-alice/logout"

    respx.post(token_url).respond(
        200, json={"access_token": "t"}, headers={"content-type": "application/json"}
    )
    respx.get(user_url).respond(
        200,
        json={
            "id": "kc-alice",
            "username": "alice",
            "email": "alice@example.com",
        },
    )
    respx.post(logout_url).respond(403)

    resp = client.post(
        f"/admin/users/kc-alice/sessions/revoke-sso?realm_id={realm.id}",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["ok"] is False
    assert "manage-users" in body["error"]
    assert resp.status_code != 500


@respx.mock
def test_keycloak_logout_success_calls_exact_endpoint(client, db_session: Session):
    settings = _test_settings()
    realm = _make_realm(db_session, settings)

    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    user_url = "https://kc.example.com/admin/realms/demo/users/kc-alice"
    logout_url = "https://kc.example.com/admin/realms/demo/users/kc-alice/logout"

    respx.post(token_url).respond(
        200, json={"access_token": "t"}, headers={"content-type": "application/json"}
    )
    respx.get(user_url).respond(
        200,
        json={
            "id": "kc-alice",
            "username": "alice",
            "email": "alice@example.com",
        },
    )
    logout_route = respx.post(logout_url).respond(204)

    resp = client.post(
        f"/admin/users/kc-alice/sessions/revoke-sso?realm_id={realm.id}",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["keycloak_user_id"] == "kc-alice"
    assert "cookie_refresh" in body["residual_note"]
    assert logout_route.called
    assert logout_route.calls[0].request.method == "POST"
    assert str(logout_route.calls[0].request.url) == logout_url

    audits = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "sessions.revoke_sso")
        .all()
    )
    assert len(audits) == 1
    assert audits[0].details["ok"] is True


@respx.mock
def test_disconnect_kc_user_missing_still_clears_native_and_portal(
    client, db_session: Session
):
    """Even when Keycloak lookup fails, disconnect must revoke bastion_session + drop portal rows."""
    from datetime import timedelta

    from app.models import OidcSession

    settings = _test_settings()
    realm = _make_realm(db_session, settings)
    now = datetime.now(timezone.utc)
    email = "l.guyot@bastia.aeroport.fr"

    db_session.add(
        ActiveSession(
            id="portal-guyot",
            kind="user",
            user_email=email,
            username="l.guyot",
            realm=realm.slug,
            protocol="OIDC",
            target="portal",
            status="active",
            started_at=now,
            last_seen_at=now,
        )
    )
    db_session.add(
        OidcSession(
            jti="jti-guyot-1",
            sub="kc-sub-guyot",
            username=email,
            realm=realm.slug,
            issued_at=now,
            expires_at=now + timedelta(hours=8),
            revoked=False,
        )
    )
    db_session.commit()

    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    respx.post(token_url).respond(
        200, json={"access_token": "t"}, headers={"content-type": "application/json"}
    )
    # fetch by id (email as path) → 404; exact email/username → []; search → []
    respx.get(url__regex=r".*/admin/realms/demo/users.*").respond(200, json=[])
    respx.get(
        f"https://kc.example.com/admin/realms/demo/users/{email}"
    ).respond(404)

    resp = client.post(
        f"/admin/users/{email}/sessions/disconnect?realm_id={realm.id}",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["sso"]["ok"] is False
    assert "introuvable" in body["sso"]["error"].lower()
    assert body["sso"]["native_oidc_revoked"] >= 1
    assert body["sso"]["portal_rows_removed"] >= 1

    oidc = db_session.query(OidcSession).filter_by(jti="jti-guyot-1").one()
    assert oidc.revoked is True
    assert oidc.revoked_reason == "admin_disconnect"
    assert (
        db_session.query(ActiveSession).filter_by(id="portal-guyot").first() is None
    )


@respx.mock
def test_revoke_sso_exact_email_lookup(client, db_session: Session):
    settings = _test_settings()
    realm = _make_realm(db_session, settings)
    email = "alice@example.com"

    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    respx.post(token_url).respond(
        200, json={"access_token": "t"}, headers={"content-type": "application/json"}
    )
    # UUID fetch of email string → 404
    respx.get(
        f"https://kc.example.com/admin/realms/demo/users/{email}"
    ).respond(404)
    respx.get(
        url__regex=r".*/admin/realms/demo/users\?email=.*exact=true.*"
    ).respond(
        200,
        json=[{"id": "kc-alice", "username": "alice", "email": email}],
    )
    logout_route = respx.post(
        "https://kc.example.com/admin/realms/demo/users/kc-alice/logout"
    ).respond(204)

    resp = client.post(
        f"/admin/users/{email}/sessions/revoke-sso?realm_id={realm.id}",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert logout_route.called


@respx.mock
def test_disconnect_revoke_all_ok_keycloak_logout_fail_separate_results(
    client, db_session: Session
):
    settings = _test_settings()
    realm = _make_realm(db_session, settings)
    _app_session(db_session, sid="s1", target="wiki")

    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    user_url = "https://kc.example.com/admin/realms/demo/users/kc-alice"
    logout_url = "https://kc.example.com/admin/realms/demo/users/kc-alice/logout"

    respx.post(token_url).respond(
        200, json={"access_token": "t"}, headers={"content-type": "application/json"}
    )
    respx.get(user_url).respond(
        200,
        json={
            "id": "kc-alice",
            "username": "alice",
            "email": "alice@example.com",
        },
    )
    respx.post(logout_url).respond(403)

    resp = client.post(
        f"/admin/users/kc-alice/sessions/disconnect?realm_id={realm.id}",
        headers={**ADMIN_HEADERS, "accept": "application/json"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["app_sessions"]["ok"] is True
    assert body["app_sessions"]["revoked_count"] == 1
    assert body["sso"]["ok"] is False
    assert "manage-users" in body["sso"]["error"]
    assert body["breakglass"]["included"] is False
    # Not a misleading global success
    assert body.get("ok") is not True


@respx.mock
def test_disconnect_revoke_all_fail_keycloak_logout_ok_separate_results(
    client, db_session: Session
):
    settings = _test_settings()
    realm = _make_realm(db_session, settings)

    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    user_url = "https://kc.example.com/admin/realms/demo/users/kc-alice"
    logout_url = "https://kc.example.com/admin/realms/demo/users/kc-alice/logout"

    respx.post(token_url).respond(
        200, json={"access_token": "t"}, headers={"content-type": "application/json"}
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

    with patch(
        "app.admin.user_sessions.revoke_all_app_sessions_for_user",
        side_effect=ValueError("échec volontaire revoke-all"),
    ):
        resp = client.post(
            f"/admin/users/kc-alice/sessions/disconnect?realm_id={realm.id}",
            headers={**ADMIN_HEADERS, "accept": "application/json"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["app_sessions"]["ok"] is False
    assert "échec volontaire" in body["app_sessions"]["error"]
    assert body["sso"]["ok"] is True
    assert body["sso"]["keycloak_user_id"] == "kc-alice"
