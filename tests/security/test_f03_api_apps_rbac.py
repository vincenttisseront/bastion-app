"""F-03: GET /api/apps must honour AccessGrant (not dump all enabled apps)."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import App, RBACGroup
from app.rbac.effective_access_service import get_effective_apps_for_user
from app.rbac.grants_service import AccessGrantCreate, create_grant

USER_HEADERS = {
    "X-Email": "alice@example.com",
    "X-Preferred-Username": "alice",
    "X-User": "alice",
    "X-User-Id": "kc-alice-f03",
    "X-Groups": "team-ops",
}

OTHER_HEADERS = {
    "X-Email": "bob@example.com",
    "X-Preferred-Username": "bob",
    "X-User": "bob",
    "X-User-Id": "kc-bob-f03",
    "X-Groups": "other-team",
}

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "portal.admin",
    "X-User": "portal.admin",
    "X-User-Id": "kc-admin-f03",
    "X-Groups": "portal-admins",
}


def _seed_two_apps(db: Session) -> tuple[App, App]:
    a = App(
        slug="allowed-app",
        label="Allowed",
        upstream_url="https://allowed.example/",
        enabled=True,
        access_mode="sso_gate",
    )
    b = App(
        slug="secret-app",
        label="Secret",
        upstream_url="https://secret.internal/",
        enabled=True,
        access_mode="sso_gate",
    )
    db.add_all([a, b])
    db.commit()
    db.refresh(a)
    db.refresh(b)
    return a, b


def test_api_apps_list_filtered_to_effective_grants(
    client: TestClient, db_session: Session
):
    allowed, secret = _seed_two_apps(db_session)
    group = RBACGroup(name="team-ops")
    db_session.add(group)
    db_session.commit()
    db_session.refresh(group)
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="application",
            application_id=allowed.id,
            access_level="launch",
        ),
        granted_by="test",
    )
    db_session.commit()

    resp = client.get("/api/apps", headers=USER_HEADERS)
    assert resp.status_code == 200
    slugs = {row["slug"] for row in resp.json()}
    assert slugs == {"allowed-app"}
    assert "secret-app" not in slugs
    assert "upstream_url" not in str(resp.json()) or all(
        row["slug"] != "secret-app" for row in resp.json()
    )

    effective = get_effective_apps_for_user(
        db_session,
        keycloak_user_id="kc-alice-f03",
        group_names=["team-ops"],
    )
    assert {e.app.slug for e in effective} == slugs


def test_api_apps_get_hides_ungranted_app(client: TestClient, db_session: Session):
    allowed, secret = _seed_two_apps(db_session)
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-alice-f03",
            resource_type="application",
            application_id=allowed.id,
            access_level="view",
        ),
        granted_by="test",
    )
    db_session.commit()

    ok = client.get("/api/apps/allowed-app", headers=USER_HEADERS)
    assert ok.status_code == 200
    denied = client.get("/api/apps/secret-app", headers=USER_HEADERS)
    assert denied.status_code == 404
    # User with no grants at all
    empty = client.get("/api/apps", headers=OTHER_HEADERS)
    assert empty.status_code == 200
    assert empty.json() == []


def test_api_apps_admin_still_sees_full_catalogue(
    client: TestClient, db_session: Session
):
    _seed_two_apps(db_session)
    resp = client.get("/api/apps", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    slugs = {row["slug"] for row in resp.json()}
    assert {"allowed-app", "secret-app"} <= slugs
