"""User portal (/apps) — effective access, redirects, launch-ping."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import App, AuditLog, RBACGroup
from app.rbac.effective_access_service import (
    get_effective_apps_for_user,
)
from app.rbac.grants_service import AccessGrantCreate, create_grant


USER_HEADERS = {
    "X-Email": "alice@example.com",
    "X-Preferred-Username": "alice",
    "X-User-Id": "kc-user-alice",
    "X-Groups": "team-ops",
}

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
}

VIEW_ONLY_HEADERS = {
    "X-Email": "viewer@example.com",
    "X-Preferred-Username": "viewer",
    "X-User-Id": "kc-user-viewer",
    "X-Groups": "",
}


def _app(db: Session, *, slug: str, label: str, enabled: bool = True, **kwargs) -> App:
    app = App(
        slug=slug,
        label=label,
        upstream_url=kwargs.pop("upstream_url", f"https://{slug}.example.com/"),
        enabled=enabled,
        access_mode=kwargs.pop("access_mode", "sso_gate"),
        public_fqdn=kwargs.pop("public_fqdn", None),
        **kwargs,
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def _group(db: Session, name: str) -> RBACGroup:
    group = RBACGroup(name=name, path=f"/{name}")
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


def test_user_portal_direct_grant(db_session: Session):
    app = _app(db_session, slug="wiki", label="Wiki")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-user-alice",
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db_session.commit()

    apps = get_effective_apps_for_user(
        db_session, keycloak_user_id="kc-user-alice", group_names=[]
    )
    assert len(apps) == 1
    assert apps[0].app.slug == "wiki"
    assert apps[0].access_level == "launch"
    assert apps[0].sources == ["direct"]
    assert apps[0].can_launch is True


def test_user_portal_group_grant(db_session: Session):
    app = _app(db_session, slug="crm", label="CRM")
    group = _group(db_session, "team-ops")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="application",
            application_id=app.id,
            access_level="manage",
        ),
        "admin",
    )
    db_session.commit()

    apps = get_effective_apps_for_user(
        db_session, keycloak_user_id=None, group_names=["team-ops"]
    )
    assert len(apps) == 1
    assert apps[0].app.slug == "crm"
    assert apps[0].access_level == "manage"
    assert apps[0].sources == ["via groupe team-ops"]


def test_native_oidc_empty_groups_hides_group_grants_keeps_direct(db_session: Session):
    """Regression: native bastion_session without groups looked like SSO with only direct apps.

    Group App grants (Dolibarr, Grommunio, …) require X-Groups / OIDC groups claim;
    a direct Transfer grant still appears when groups are missing.
    """
    transfer = _app(db_session, slug="transfer", label="Transfer")
    dolibarr = _app(db_session, slug="dolibarr", label="Dolibarr")
    grommunio = _app(db_session, slug="grommunio", label="Grommunio")
    group = _group(db_session, "ARSYSTEMS-Users")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-vincent",
            resource_type="application",
            application_id=transfer.id,
            access_level="launch",
        ),
        "admin@breakglass.local",
    )
    for app in (dolibarr, grommunio):
        create_grant(
            db_session,
            AccessGrantCreate(
                subject_type="group",
                rbac_group_id=group.id,
                resource_type="application",
                application_id=app.id,
                access_level="launch",
            ),
            "admin@breakglass.local",
        )
    db_session.commit()

    broken = get_effective_apps_for_user(
        db_session, keycloak_user_id="kc-vincent", group_names=[]
    )
    assert [e.app.slug for e in broken] == ["transfer"]

    fixed = get_effective_apps_for_user(
        db_session,
        keycloak_user_id="kc-vincent",
        group_names=["ARSYSTEMS-Users"],
    )
    assert {e.app.slug for e in fixed} == {"transfer", "dolibarr", "grommunio"}


def test_apps_portal_renders_group_grants_from_x_groups(client: TestClient, db_session: Session):
    transfer = _app(db_session, slug="transfer", label="Transfer")
    dolibarr = _app(db_session, slug="dolibarr", label="Dolibarr")
    group = _group(db_session, "ARSYSTEMS-Users")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-vincent",
            resource_type="application",
            application_id=transfer.id,
            access_level="launch",
        ),
        "admin@breakglass.local",
    )
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="application",
            application_id=dolibarr.id,
            access_level="launch",
        ),
        "admin@breakglass.local",
    )
    db_session.commit()

    empty = client.get(
        "/apps",
        headers={
            "X-Email": "vincent.tisseront@ar-systems.fr",
            "X-Preferred-Username": "vincent.tisseront",
            "X-User-Id": "kc-vincent",
            "X-Groups": "",
            "X-Portal-Realm-Slug": "ar-systems",
        },
    )
    assert empty.status_code == 200
    assert "Transfer" in empty.text
    assert "Dolibarr" not in empty.text
    assert "1 application accessible" in empty.text or "1 application" in empty.text

    ok = client.get(
        "/apps",
        headers={
            "X-Email": "vincent.tisseront@ar-systems.fr",
            "X-Preferred-Username": "vincent.tisseront",
            "X-User-Id": "kc-vincent",
            "X-Groups": "ARSYSTEMS-Users",
            "X-Portal-Realm-Slug": "ar-systems",
        },
    )
    assert ok.status_code == 200
    assert "Transfer" in ok.text
    assert "Dolibarr" in ok.text


def test_user_portal_view_only_disabled_tile(client: TestClient, db_session: Session):
    app = _app(db_session, slug="reports", label="Reports")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-user-viewer",
            resource_type="application",
            application_id=app.id,
            access_level="view",
        ),
        "admin",
    )
    db_session.commit()

    resp = client.get("/apps", headers=VIEW_ONLY_HEADERS)
    assert resp.status_code == 200
    assert "Reports" in resp.text
    assert "app-tile--disabled" in resp.text
    assert "Lecture seule" in resp.text
    assert 'href="https://reports.example.com/"' not in resp.text
    assert "mode-badge" not in resp.text
    assert "SSO Gate" not in resp.text
    assert "Sous-domaine" not in resp.text
    assert "access_mode" not in resp.text
    assert 'id="app-reports"' in resp.text
    assert "grant" not in resp.text.lower()
    assert "Mon profil" in resp.text
    assert 'href="/profile"' in resp.text
    assert "admin-desc" not in resp.text
    assert "Bonjour Viewer" in resp.text or "Bonjour viewer" in resp.text


def test_user_portal_empty_state(client: TestClient):
    resp = client.get("/apps", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert "Aucune application" in resp.text
    assert "portal-empty" in resp.text
    assert "Administration" not in resp.text
    assert "portal-shell" in resp.text


def test_user_portal_admin_link_hidden_for_non_admin(
    client: TestClient, db_session: Session
):
    app = _app(db_session, slug="wiki", label="Wiki")
    group = _group(db_session, "team-ops")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db_session.commit()

    resp = client.get("/apps", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert "Wiki" in resp.text
    assert "Administration" not in resp.text
    assert 'href="/dashboard"' not in resp.text
    assert "mode-badge" not in resp.text
    assert "Gérée" not in resp.text
    assert "Ouvrir" in resp.text
    assert "app-tile--okta" in resp.text
    assert "data-tile-more" in resp.text


def test_user_portal_manage_badge_only(client: TestClient, db_session: Session):
    app = _app(db_session, slug="crm", label="CRM")
    group = _group(db_session, "team-ops")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="application",
            application_id=app.id,
            access_level="manage",
        ),
        "admin",
    )
    db_session.commit()

    resp = client.get("/apps", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert "Gérée" in resp.text
    assert "mode-badge" not in resp.text
    assert "manage" not in resp.text
    assert "access_mode" not in resp.text
    assert "Bonjour Alice" in resp.text


def test_user_portal_shows_description_when_set(client: TestClient, db_session: Session):
    app = _app(db_session, slug="wiki", label="Wiki")
    app.description = "Base de connaissances métier"
    db_session.commit()
    group = _group(db_session, "team-ops")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db_session.commit()

    resp = client.get("/apps", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert "Base de connaissances métier" in resp.text
    assert "app-tile-menu-desc" in resp.text
    assert "admin-desc" not in resp.text
    assert "app-tile--okta" in resp.text


def test_user_portal_admin_link_visible_in_dropdown(client: TestClient):
    """Administration must appear inside the user-menu dropdown for portal admins."""
    headers = {
        "X-Email": "vincent.tisseront@ar-systems.fr",
        "X-Preferred-Username": "vincent.tisseront",
        "X-Groups": "/portal-admins",
    }
    resp = client.get("/apps", headers=headers)
    assert resp.status_code == 200
    assert "portal-user-menu" in resp.text
    assert "data-portal-admin-link" in resp.text
    assert "Administration" in resp.text
    assert 'href="/dashboard"' in resp.text
    # Link sits in the dropdown nav, not as a standalone topbar button.
    assert "portal-user-dropdown" in resp.text
    assert resp.text.index("portal-user-dropdown") < resp.text.index("Administration")


def test_user_portal_admin_link_absent_in_dropdown_for_user(client: TestClient):
    resp = client.get("/apps", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert "portal-user-menu" in resp.text
    assert "data-portal-admin-link" not in resp.text
    assert "Administration" not in resp.text
    assert 'href="/dashboard"' not in resp.text


def test_user_portal_admin_link_path_style_groups(client: TestClient):
    """Keycloak often forwards groups as /portal-admins — still grant Administration."""
    headers = {
        "X-Email": "vincent@example.com",
        "X-Preferred-Username": "vincent.tisseront",
        "X-Groups": "/portal-admins,/team-ops",
    }
    resp = client.get("/apps", headers=headers)
    assert resp.status_code == 200
    assert "Administration" in resp.text
    assert 'href="/dashboard"' in resp.text


def test_user_portal_disabled_app_absent(db_session: Session):
    app = _app(db_session, slug="legacy", label="Legacy", enabled=False)
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-user-alice",
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db_session.commit()

    apps = get_effective_apps_for_user(
        db_session, keycloak_user_id="kc-user-alice", group_names=[]
    )
    assert apps == []


def test_user_portal_dedup_multi_source_keeps_highest(db_session: Session):
    app = _app(db_session, slug="intranet", label="Intranet")
    group = _group(db_session, "team-ops")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="application",
            application_id=app.id,
            access_level="view",
        ),
        "admin",
    )
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-user-alice",
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db_session.commit()

    apps = get_effective_apps_for_user(
        db_session,
        keycloak_user_id="kc-user-alice",
        group_names=["team-ops"],
    )
    assert len(apps) == 1
    assert apps[0].access_level == "launch"
    assert "direct" in apps[0].sources
    assert any(s.startswith("via groupe") for s in apps[0].sources)


def test_user_portal_dashboard_redirect_non_admin(client: TestClient):
    resp = client.get("/dashboard", headers=USER_HEADERS, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/apps"


def test_user_portal_admin_link_visible(client: TestClient, db_session: Session):
    app = _app(db_session, slug="wiki", label="Wiki")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-admin-extra",
            user_display_cache="admin-extra",
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db_session.commit()

    resp = client.get("/apps", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Administration" in resp.text
    assert 'href="/dashboard"' in resp.text


def test_user_portal_admin_keeps_dashboard(client: TestClient):
    resp = client.get("/dashboard", headers=ADMIN_HEADERS, follow_redirects=False)
    assert resp.status_code == 200
    assert "Bastion" in resp.text or "métrique" in resp.text.lower() or "Dashboard" in resp.text or "audit" in resp.text.lower()


def test_user_portal_launch_urls_by_mode(client: TestClient, db_session: Session):
    sso = _app(
        db_session,
        slug="sso-app",
        label="SSO App",
        access_mode="sso_gate",
        upstream_url="https://public.wiki.example/",
    )
    sub = _app(
        db_session,
        slug="sub-app",
        label="Sub App",
        access_mode="subdomain_proxy",
        upstream_url="http://10.0.0.1:8080/",
        public_fqdn="sub.example.fr",
    )
    legacy = _app(
        db_session,
        slug="legacy-app",
        label="Legacy App",
        access_mode="legacy_path_proxy",
        upstream_url="http://10.0.0.2/",
    )
    group = _group(db_session, "team-ops")
    for app in (sso, sub, legacy):
        create_grant(
            db_session,
            AccessGrantCreate(
                subject_type="group",
                rbac_group_id=group.id,
                resource_type="application",
                application_id=app.id,
                access_level="launch",
            ),
            "admin",
        )
    db_session.commit()

    resp = client.get("/apps", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert 'href="https://public.wiki.example/"' in resp.text
    assert 'href="https://sub.example.fr"' in resp.text
    assert 'href="/proxy/legacy-app/"' in resp.text


def test_user_portal_launch_ping_audits(client: TestClient, db_session: Session):
    app = _app(db_session, slug="wiki", label="Wiki")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-user-alice",
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db_session.commit()

    resp = client.post(f"/api/apps/{app.id}/launch-ping", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    entry = db_session.query(AuditLog).filter_by(action="app_launch").first()
    assert entry is not None
    assert entry.target == "wiki"
    assert entry.details["sources"] == ["direct"]


def test_user_portal_launch_ping_view_only_forbidden(
    client: TestClient, db_session: Session
):
    app = _app(db_session, slug="reports", label="Reports")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-user-viewer",
            resource_type="application",
            application_id=app.id,
            access_level="view",
        ),
        "admin",
    )
    db_session.commit()

    resp = client.post(f"/api/apps/{app.id}/launch-ping", headers=VIEW_ONLY_HEADERS)
    assert resp.status_code == 403


def test_user_portal_root_redirects_to_apps(client: TestClient):
    resp = client.get("/", headers=USER_HEADERS, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/apps"


def test_user_portal_admin_route_redirects_non_admin(client: TestClient):
    resp = client.get("/admin/apps", headers=USER_HEADERS, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/apps"
