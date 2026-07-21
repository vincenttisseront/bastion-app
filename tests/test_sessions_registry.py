"""Active sessions registry — portal users + app launches."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import ActiveSession, App
from app.rbac.grants_service import AccessGrantCreate, create_grant


USER_HEADERS = {
    "X-Email": "alice@example.com",
    "X-Preferred-Username": "alice",
    "X-User-Id": "kc-user-alice",
    "X-Groups": "team-ops",
    "X-Portal-Realm-Slug": "ar-systems",
}

OTHER_HEADERS = {
    "X-Email": "bob@example.com",
    "X-Preferred-Username": "bob",
    "X-User-Id": "kc-user-bob",
    "X-Groups": "",
    "X-Portal-Realm-Slug": "ar-systems",
}

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
    "X-Portal-Realm-Slug": "ar-systems",
}


def _app(db: Session, *, slug: str = "wiki", label: str = "Wiki") -> App:
    app = App(
        slug=slug,
        label=label,
        upstream_url=f"https://{slug}.example.com/",
        enabled=True,
        access_mode="sso_gate",
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def _grant_launch(db: Session, app: App, keycloak_user_id: str) -> None:
    create_grant(
        db,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id=keycloak_user_id,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db.commit()


def test_apps_creates_user_session(client: TestClient, db_session: Session):
    resp = client.get("/apps", headers=USER_HEADERS)
    assert resp.status_code == 200

    rows = db_session.query(ActiveSession).all()
    assert len(rows) == 1
    assert rows[0].kind == "user"
    assert rows[0].target == "portal"
    assert rows[0].protocol == "OIDC"
    assert rows[0].user_email == "alice@example.com"
    assert rows[0].status == "active"


def test_launch_ping_creates_app_session(client: TestClient, db_session: Session):
    app = _app(db_session)
    _grant_launch(db_session, app, "kc-user-alice")

    client.get("/apps", headers=USER_HEADERS)
    ping = client.post(f"/api/apps/{app.id}/launch-ping", headers=USER_HEADERS)
    assert ping.status_code == 200
    assert ping.json()["ok"] is True

    kinds = {r.kind for r in db_session.query(ActiveSession).all()}
    assert kinds == {"user", "app"}
    app_row = db_session.query(ActiveSession).filter_by(kind="app").one()
    assert app_row.target == "wiki"
    assert app_row.protocol == "HTTPS"


def test_sessions_page_lists_after_touch(client: TestClient, db_session: Session):
    client.get("/apps", headers=USER_HEADERS)
    resp = client.get("/sessions", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert "Aucune session active" not in resp.text
    assert "alice" in resp.text
    assert "portal" in resp.text


def test_non_admin_sees_only_own_sessions(client: TestClient, db_session: Session):
    client.get("/apps", headers=USER_HEADERS)
    client.get("/apps", headers=OTHER_HEADERS)

    api = client.get("/api/sessions", headers=USER_HEADERS)
    assert api.status_code == 200
    sessions = api.json()["sessions"]
    assert len(sessions) == 1
    assert sessions[0]["user_email"] == "alice@example.com"

    admin_api = client.get("/api/sessions", headers=ADMIN_HEADERS)
    assert admin_api.status_code == 200
    assert len(admin_api.json()["sessions"]) >= 2


def test_sessions_kind_filter(client: TestClient, db_session: Session):
    app = _app(db_session)
    _grant_launch(db_session, app, "kc-user-alice")
    client.get("/apps", headers=USER_HEADERS)
    client.post(f"/api/apps/{app.id}/launch-ping", headers=USER_HEADERS)

    users = client.get("/api/sessions?kind=user", headers=ADMIN_HEADERS).json()["sessions"]
    apps = client.get("/api/sessions?kind=app", headers=ADMIN_HEADERS).json()["sessions"]
    assert all(s["kind"] == "user" for s in users)
    assert all(s["kind"] == "app" for s in apps)
    assert any(s["target"] == "wiki" for s in apps)


def test_sessions_grouped_by_user(client: TestClient, db_session: Session):
    app = _app(db_session)
    _grant_launch(db_session, app, "kc-user-alice")
    client.get("/apps", headers={**USER_HEADERS, "X-Forwarded-For": "192.168.2.167, 10.5.0.3"})
    client.post(
        f"/api/apps/{app.id}/launch-ping",
        headers={**USER_HEADERS, "X-Forwarded-For": "192.168.2.167, 10.5.0.3"},
    )

    api = client.get("/api/sessions", headers=USER_HEADERS)
    assert api.status_code == 200
    body = api.json()
    assert len(body["sessions"]) == 2
    assert len(body["groups"]) == 1
    group = body["groups"][0]
    assert group["user_email"] == "alice@example.com"
    assert group["session_count"] == 2
    assert group["source_ip"] == "192.168.2.167"
    targets = {s["target"] for s in group["sessions"]}
    assert targets == {"portal", "wiki"}


def test_isolate_session(client: TestClient, db_session: Session):
    client.get("/apps", headers=USER_HEADERS)
    row = db_session.query(ActiveSession).filter_by(kind="user").one()
    resp = client.post(
        f"/admin/sessions/{row.id}/isolate",
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 200
    db_session.refresh(row)
    assert row.status == "isolated"
