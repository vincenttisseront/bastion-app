"""Topbar user menu — profile dropdown on admin and portal chrome."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.rbac.grants_service import AccessGrantCreate, create_grant

GROUP_ADMIN_HEADERS = {
    "X-Email": "group-admin@example.com",
    "X-Preferred-Username": "group.admin",
    "X-User": "group.admin",
    "X-User-Id": "kc-group-admin",
    "X-Groups": "portal-admins",
}

GRANT_ADMIN_HEADERS = {
    "X-Email": "grant-admin@example.com",
    "X-Preferred-Username": "grant.admin",
    "X-User": "grant.admin",
    "X-User-Id": "kc-grant-admin",
    "X-Groups": "ARSYSTEMS-Users",
}


def _assert_profile_dropdown(html: str) -> None:
    assert "portal-user-menu" in html
    assert "portal-user-dropdown" in html
    assert 'href="/profile"' in html
    assert "Mon profil" in html
    assert 'href="/logout"' in html
    assert "portal-avatar" in html
    # Profile link lives inside the dropdown, not as a stray topbar link.
    assert html.index("portal-user-dropdown") < html.index('href="/profile"')


def _grant_portal_admin(db: Session, *, keycloak_user_id: str, display: str) -> None:
    create_grant(
        db,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id=keycloak_user_id,
            user_display_cache=display,
            resource_type="system_role",
            system_role="portal_admin",
            access_level="view",
        ),
        "seed-admin",
    )
    db.commit()


def test_topbar_profile_dropdown_on_admin_dashboard(client: TestClient):
    resp = client.get("/dashboard", headers=GROUP_ADMIN_HEADERS)
    assert resp.status_code == 200
    _assert_profile_dropdown(resp.text)
    assert "group.admin" in resp.text


def test_topbar_profile_dropdown_on_portal_apps(client: TestClient):
    resp = client.get("/apps", headers=GROUP_ADMIN_HEADERS)
    assert resp.status_code == 200
    _assert_profile_dropdown(resp.text)


def test_topbar_profile_dropdown_grant_admin_on_dashboard(
    client: TestClient, db_session: Session
):
    _grant_portal_admin(
        db_session, keycloak_user_id="kc-grant-admin", display="grant.admin"
    )
    resp = client.get("/dashboard", headers=GRANT_ADMIN_HEADERS)
    assert resp.status_code == 200
    _assert_profile_dropdown(resp.text)
    assert "grant.admin" in resp.text


def test_topbar_no_plain_logout_button_on_admin_dashboard(client: TestClient):
    """Regression: admin topbar must not fall back to plain text + logout link."""
    resp = client.get("/dashboard", headers=GROUP_ADMIN_HEADERS)
    assert resp.status_code == 200
    assert 'class="logout-btn"' not in resp.text
