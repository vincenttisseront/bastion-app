"""Admin sidebar accordion groups (Administration section)."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import PendingUser

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def test_admin_sidebar_has_accordion_groups(client: TestClient):
    resp = client.get("/dashboard", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    assert "Administration" in html
    assert 'data-nav-accordion="general"' in html
    assert 'data-nav-accordion="access"' in html
    assert 'data-nav-accordion="content"' in html
    assert 'data-nav-accordion="infra"' in html
    assert "Général" in html
    assert "Accès &amp; sécurité" in html or "Accès & sécurité" in html
    assert "Contenu &amp; apps" in html or "Contenu & apps" in html
    assert "Infra &amp; supervision" in html or "Infra & supervision" in html
    assert 'data-sidebar-admin-accordion' in html
    assert 'id="sidebar-search"' in html
    assert 'href="/admin/rbac/overview"' in html
    assert 'href="/admin/pending-users"' in html
    assert 'data-nav-subgroup="pending"' in html


def test_admin_sidebar_opens_group_for_active_route(client: TestClient):
    import re

    resp = client.get("/admin/infrastructure", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    # Active group must be open in markup; siblings stay closed (strict accordion).
    assert 'data-nav-accordion="infra"' in html
    assert 'href="/admin/infrastructure"' in html
    assert "active" in html.split('href="/admin/infrastructure"', 1)[1][:80]

    def details_open_for(group_id: str) -> bool:
        marker = f'data-nav-accordion="{group_id}"'
        idx = html.index(marker)
        tag_end = html.index(">", idx)
        return re.search(r"\bopen\b", html[idx:tag_end]) is not None

    assert details_open_for("infra") is True
    assert details_open_for("general") is False
    assert details_open_for("access") is False
    assert details_open_for("content") is False


def test_admin_sidebar_pending_badge(client: TestClient, db_session: Session):
    db_session.add(
        PendingUser(
            user_email="pending.nav@example.com",
            username="pending.nav",
            realm_slug="ar-systems",
            status="pending",
        )
    )
    db_session.commit()

    resp = client.get("/dashboard", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    assert 'data-nav-accordion="content"' in html
    content_block = html.split('data-nav-accordion="content"', 1)[1].split(
        "data-nav-accordion=", 1
    )[0]
    # Badge on Contenu group header (visible even when the group is collapsed).
    assert "nav-accordion-badge" in content_block
    assert "nouveaux utilisateurs en attente" in content_block
    assert 'href="/admin/pending-users"' in content_block
    assert "nav-badge" in content_block.split("Nouveaux users", 1)[1][:200]


def test_non_admin_sidebar_hides_administration(client: TestClient):
    resp = client.get(
        "/dashboard",
        headers={"X-Email": "user@example.com", "X-Groups": "users"},
    )
    assert resp.status_code == 200
    html = resp.text
    assert "Administration" not in html
    assert 'data-nav-accordion="general"' not in html
    assert 'href="/admin/rbac/overview"' not in html
    assert 'href="/admin/rbac"' not in html
