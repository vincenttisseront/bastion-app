"""Navigation RBAC : une entrée sidebar + onglets Groupes / Utilisateurs / Matrice."""

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _assert_single_rbac_nav(html: str) -> None:
    assert 'href="/admin/rbac" class="nav-item active"' in html
    # Une seule entrée sidebar pointant vers /admin/rbac (pas users/matrix en nav)
    assert html.count('href="/admin/rbac" class="nav-item') == 1
    assert 'href="/admin/rbac/users" class="nav-item' not in html
    assert 'href="/admin/rbac/matrix" class="nav-item' not in html


def test_rbac_groups_page_has_tabs_and_single_sidebar_entry(client):
    resp = client.get("/admin/rbac", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    _assert_single_rbac_nav(html)
    assert 'href="/admin/rbac" class="tab active"' in html
    assert 'href="/admin/rbac/users" class="tab"' in html
    assert 'href="/admin/rbac/matrix" class="tab"' in html
    assert "Gestion RBAC" in html


def test_rbac_users_page_has_tabs_and_single_sidebar_entry(client):
    resp = client.get("/admin/rbac/users", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    _assert_single_rbac_nav(html)
    assert 'href="/admin/rbac" class="tab"' in html
    assert 'href="/admin/rbac/users" class="tab active"' in html
    assert 'href="/admin/rbac/matrix" class="tab"' in html
    assert "Droits par utilisateur" in html


def test_rbac_matrix_page_has_tabs_and_single_sidebar_entry(client):
    resp = client.get("/admin/rbac/matrix", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    _assert_single_rbac_nav(html)
    assert 'href="/admin/rbac" class="tab"' in html
    assert 'href="/admin/rbac/users" class="tab"' in html
    assert 'href="/admin/rbac/matrix" class="tab active"' in html
    assert "Matrice Applications" in html
