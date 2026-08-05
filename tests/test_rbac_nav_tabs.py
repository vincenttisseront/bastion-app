"""Navigation RBAC : une entrée sidebar + onglets Vue d'ensemble / Utilisateurs / Groupes / Matrice / Gouvernance."""

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _assert_single_rbac_nav(html: str) -> None:
    assert 'href="/admin/rbac/overview" class="nav-item active"' in html or (
        'href="/admin/rbac/overview"' in html and "nav-item active" in html
    )
    # Une seule entrée sidebar RBAC (pas users/matrix en nav)
    assert html.count('data-nav-label="RBAC"') == 1
    assert 'href="/admin/rbac/users" class="nav-item' not in html
    assert 'href="/admin/rbac/matrix" class="nav-item' not in html
    assert 'href="/admin/rbac/governance" class="nav-item' not in html


def test_rbac_overview_page_has_tabs(client):
    resp = client.get("/admin/rbac/overview", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    assert 'href="/admin/rbac/overview" class="tab active"' in html
    assert "Vue d'ensemble" in html
    assert 'href="/admin/rbac/users" class="tab"' in html
    assert 'href="/admin/rbac" class="tab"' in html


def test_rbac_groups_page_has_tabs_and_single_sidebar_entry(client):
    resp = client.get("/admin/rbac", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    _assert_single_rbac_nav(html)
    assert 'href="/admin/rbac" class="tab active"' in html
    assert 'href="/admin/rbac/overview" class="tab"' in html
    assert 'href="/admin/rbac/users" class="tab"' in html
    assert 'href="/admin/rbac/matrix" class="tab"' in html
    assert 'href="/admin/rbac/governance" class="tab"' in html
    assert "Gestion" in html
    assert "page-rbac" in html or "rbac-layout" in html


def test_rbac_users_page_has_tabs_and_single_sidebar_entry(client):
    resp = client.get("/admin/rbac/users", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    _assert_single_rbac_nav(html)
    assert 'href="/admin/rbac" class="tab"' in html
    assert 'href="/admin/rbac/users" class="tab active"' in html
    assert 'href="/admin/rbac/matrix" class="tab"' in html
    assert 'href="/admin/rbac/governance" class="tab"' in html
    assert "Gestion des Utilisateurs" in html
    # Groupes block must not be duplicated as a full table under users
    assert html.count("users-groups") == 0
    assert "Gérer les groupes" in html


def test_rbac_matrix_page_has_tabs_and_single_sidebar_entry(client):
    resp = client.get("/admin/rbac/matrix", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    _assert_single_rbac_nav(html)
    assert 'href="/admin/rbac" class="tab"' in html
    assert 'href="/admin/rbac/users" class="tab"' in html
    assert 'href="/admin/rbac/matrix" class="tab active"' in html
    assert 'href="/admin/rbac/governance" class="tab"' in html
    assert "Matrice Applications" in html


def test_rbac_governance_page_has_tabs_and_single_sidebar_entry(client):
    resp = client.get("/admin/rbac/governance", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    _assert_single_rbac_nav(html)
    assert 'href="/admin/rbac/governance" class="tab active"' in html
    assert "Matrice de Permissions" in html
