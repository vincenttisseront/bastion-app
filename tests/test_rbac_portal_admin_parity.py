"""Parity: grant-only portal_admin == group-only portal_admin (routes + chrome)."""

from __future__ import annotations

import re

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import AccessGrant
from app.rbac.grants_service import AccessGrantCreate, create_grant
from app.web.user_context import looks_like_uuid

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
    "X-Groups": "ARSYSTEMS-Users",  # no PORTAL_ADMIN_GROUPS
}

# Mimics production when Preferred-Username is empty and only sub is known.
GRANT_ADMIN_UUID_HEADERS = {
    "X-Email": "",
    "X-Preferred-Username": "",
    "X-User": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "X-User-Id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "X-Groups": "ARSYSTEMS-Users",
}

UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

ADMIN_ROUTES = [
    "/dashboard",
    "/admin/dashboard",
    "/admin/apps",
    "/admin/realms",
    "/admin/rbac",
    "/admin/rbac/users",
    "/admin/rbac/matrix",
    "/admin/security",
    "/admin/logs",
    "/admin/health",
    "/sessions",
]


def _grant_portal_admin(db: Session, *, keycloak_user_id: str, display: str) -> AccessGrant:
    grant = create_grant(
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
    return grant


def test_rbac_portal_admin_parity_routes(client: TestClient, db_session: Session):
    _grant_portal_admin(
        db_session, keycloak_user_id="kc-grant-admin", display="grant.admin"
    )

    for path in ADMIN_ROUTES:
        group_resp = client.get(path, headers=GROUP_ADMIN_HEADERS, follow_redirects=False)
        grant_resp = client.get(path, headers=GRANT_ADMIN_HEADERS, follow_redirects=False)
        assert group_resp.status_code == grant_resp.status_code, (
            f"{path}: group={group_resp.status_code} grant={grant_resp.status_code}"
        )
        assert group_resp.status_code == 200, f"{path} group admin expected 200"


def test_rbac_portal_admin_parity_sidebar_admin_section(
    client: TestClient, db_session: Session
):
    _grant_portal_admin(
        db_session, keycloak_user_id="kc-grant-admin", display="grant.admin"
    )

    group_html = client.get("/dashboard", headers=GROUP_ADMIN_HEADERS).text
    grant_html = client.get("/dashboard", headers=GRANT_ADMIN_HEADERS).text

    for html in (group_html, grant_html):
        assert "Administration" in html
        assert 'href="/admin/rbac/overview"' in html or 'href="/admin/rbac"' in html
        assert 'href="/admin/realms"' in html
        assert 'href="/admin/apps"' in html
        assert ">RBAC<" in html or ">RBAC</a>" in html or "\n      RBAC\n" in html


def test_rbac_portal_admin_parity_topbar_never_shows_uuid(
    client: TestClient, db_session: Session
):
    uid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    _grant_portal_admin(db_session, keycloak_user_id=uid, display="bob.test")

    resp = client.get("/dashboard", headers=GRANT_ADMIN_UUID_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    assert "bob.test" in html
    # Topbar / sidebar must not expose the raw Keycloak subject.
    assert uid not in html or html.count(uid) == 0
    assert not looks_like_uuid("bob.test")
    # Safety: no UUID-shaped token in the user-name / topbar chrome.
    chrome = html
    # Allow UUID only if it appears in non-user chrome (should not).
    matches = UUID_RE.findall(chrome)
    assert matches == [], f"UUID leaked into page chrome: {matches}"


def test_rbac_portal_admin_parity_apps_admin_link(
    client: TestClient, db_session: Session
):
    _grant_portal_admin(
        db_session, keycloak_user_id="kc-grant-admin", display="grant.admin"
    )
    group = client.get("/apps", headers=GROUP_ADMIN_HEADERS)
    grant = client.get("/apps", headers=GRANT_ADMIN_HEADERS)
    assert group.status_code == 200
    assert grant.status_code == 200
    assert "Administration" in group.text
    assert "Administration" in grant.text
    assert 'data-portal-admin-link' in group.text
    assert 'data-portal-admin-link' in grant.text
