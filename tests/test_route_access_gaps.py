"""Access-control gaps: /api/apps reads, /audit, /api/metrics."""

from __future__ import annotations

from app.models import App
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

USER_HEADERS = {
    "X-Email": "user@example.com",
    "X-Preferred-Username": "end.user",
    "X-User": "end.user",
    "X-User-Id": "kc-end-user",
    "X-Groups": "ARSYSTEMS-Users",
}

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "portal.admin",
    "X-User": "portal.admin",
    "X-User-Id": "kc-portal-admin",
    "X-Groups": "portal-admins",
}


def _seed_app(db: Session) -> App:
    app = App(
        slug="coverage-app",
        label="Coverage App",
        upstream_url="https://upstream.example/",
        enabled=True,
        access_mode="sso_gate",
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def test_api_apps_list_requires_auth(client: TestClient, db_session: Session):
    app = _seed_app(db_session)
    anon = client.get("/api/apps")
    assert anon.status_code in (401, 403)
    # End user without AccessGrant must not see the seeded app (F-03).
    ok = client.get("/api/apps", headers=USER_HEADERS)
    assert ok.status_code == 200
    assert ok.json() == []
    # Portal admin still sees the full enabled catalogue.
    admin = client.get("/api/apps", headers=ADMIN_HEADERS)
    assert admin.status_code == 200
    assert any(a["slug"] == app.slug for a in admin.json())


def test_api_apps_get_requires_auth(client: TestClient, db_session: Session):
    app = _seed_app(db_session)
    anon = client.get("/api/apps/coverage-app")
    assert anon.status_code in (401, 403)
    # No grant → hide existence (404), same as list filter.
    denied = client.get("/api/apps/coverage-app", headers=USER_HEADERS)
    assert denied.status_code == 404
    ok = client.get("/api/apps/coverage-app", headers=ADMIN_HEADERS)
    assert ok.status_code == 200
    assert ok.json()["slug"] == app.slug


def test_audit_requires_admin(client: TestClient):
    user = client.get("/audit", headers=USER_HEADERS, follow_redirects=False)
    assert user.status_code in (302, 403)
    if user.status_code == 302:
        assert "/apps" in (user.headers.get("location") or "")
    admin = client.get("/audit", headers=ADMIN_HEADERS, follow_redirects=False)
    assert admin.status_code == 302
    assert "/admin/logs" in (admin.headers.get("location") or "")


def test_api_metrics_requires_admin(client: TestClient):
    user = client.get("/api/metrics", headers=USER_HEADERS)
    assert user.status_code == 403
    admin = client.get("/api/metrics", headers=ADMIN_HEADERS)
    assert admin.status_code == 200
    body = admin.json()
    assert "active_sessions" in body
