"""Global search API — role-filtered categories."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import respx
from sqlalchemy.orm import Session

from app.models import App, AuditLog, RBACGroup, RealmConfig
from app.rbac.grants_service import AccessGrantCreate, create_grant
from app.search_fuzzy import fold_text, score_query_against_fields
from tests.test_access_grants import _realm


USER_HEADERS = {
    "X-Email": "alice@example.com",
    "X-Preferred-Username": "alice",
    "X-User-Id": "kc-user-alice",
    "X-Groups": "team-ops",
    "X-Portal-Realm-Slug": "default",
}

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
    "X-Portal-Realm-Slug": "default",
}

ADMIN_CATEGORY_KEYS = ("hosts", "users", "groups", "sessions", "realms", "audit")


def _app(db: Session, *, slug: str, label: str, **kwargs) -> App:
    app = App(
        slug=slug,
        label=label,
        upstream_url=kwargs.pop("upstream_url", f"https://{slug}.example.com/"),
        enabled=kwargs.pop("enabled", True),
        description=kwargs.pop("description", None),
        access_mode=kwargs.pop("access_mode", "sso_gate"),
        **kwargs,
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def _group(db: Session, name: str = "team-ops") -> RBACGroup:
    g = RBACGroup(name=name, realm_slug="default", path=f"/{name}")
    db.add(g)
    db.commit()
    db.refresh(g)
    return g


def _grant_app(db: Session, app: App, group: RBACGroup) -> None:
    create_grant(
        db,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="application",
            application_id=app.id,
            access_level="view",
        ),
        "test",
    )
    db.commit()


def test_fold_and_score_shared():
    assert fold_text("Café") == "cafe"
    assert score_query_against_fields("grafna", ["Grafana"]) >= 0.52
    # FQDN / URL host labels must match the typed subdomain.
    assert (
        score_query_against_fields(
            "sonarqube", ["sonarqube.portal.example.com"]
        )
        >= 0.9
    )
    assert (
        score_query_against_fields(
            "sonarqube", ["https://sonarqube.example.com/dashboard"]
        )
        >= 0.9
    )
    assert score_query_against_fields("sonar", ["SonarQube"]) >= 0.85


def test_global_search_short_query_skips_subsearches(client, db_session):
    with (
        patch("app.web.global_search._search_applications") as apps,
        patch("app.web.global_search._search_groups") as groups,
        patch("app.web.global_search._search_users") as users,
    ):
        resp = client.get(
            "/api/search?q=g",
            headers={**USER_HEADERS, "Accept": "application/json"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["results"] == {}
        apps.assert_not_called()
        groups.assert_not_called()
        users.assert_not_called()


def test_global_search_user_only_applications(client, db_session):
    group = _group(db_session)
    grafana = _app(db_session, slug="grafana", label="Grafana", description="Metrics")
    _app(db_session, slug="secret-admin-app", label="Secret Admin Tool")
    _grant_app(db_session, grafana, group)

    db_session.add(
        RealmConfig(
            slug="portal",
            name="Portal Realm",
            issuer_url="https://kc.example.com/realms/EXAMPLE-CORP",
            client_id="c",
            client_secret_encrypted="x",
            redirect_uri="https://portal.example.com/oauth2/callback",
            oauth2_proxy_port=4180,
            enabled=True,
        )
    )
    db_session.add(
        AuditLog(
            actor="admin@example.com",
            action="credential.set",
            target="app:grafana",
            created_at=datetime.now(timezone.utc),
        )
    )
    db_session.commit()

    resp = client.get(
        "/api/search?q=grafna",
        headers={**USER_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert set(data["results"].keys()) == {"applications"}
    labels = [r["label"] for r in data["results"]["applications"]]
    assert "Grafana" in labels
    urls = [r["url"] for r in data["results"]["applications"]]
    assert any(u == "/apps#app-grafana" for u in urls)
    for forbidden in ADMIN_CATEGORY_KEYS:
        assert forbidden not in data["results"]


def test_global_search_admin_categories(client, db_session):
    app = _app(db_session, slug="grafana", label="Grafana")
    admin_group = RBACGroup(
        name="portal-admins", realm_slug="default", path="/portal-admins"
    )
    db_session.add(admin_group)
    db_session.commit()
    db_session.refresh(admin_group)
    _grant_app(db_session, app, admin_group)

    ops = _group(db_session, name="team-ops-searchable")
    assert ops.id

    db_session.add(
        RealmConfig(
            slug="acme-systems",
            name="Acme Systems",
            issuer_url="https://kc.example.com/realms/EXAMPLE-CORP",
            client_id="c",
            client_secret_encrypted="x",
            redirect_uri="https://portal.example.com/oauth2/callback",
            oauth2_proxy_port=4181,
            enabled=True,
            groups_sync_enabled=False,
        )
    )
    db_session.add(
        AuditLog(
            actor="admin@example.com",
            action="key_rotation",
            target="vault:fernet",
            created_at=datetime.now(timezone.utc),
        )
    )
    db_session.commit()

    resp = client.get(
        "/api/search?q=graf",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert "applications" in data["results"]
    assert any(
        r["label"] == "Grafana" for r in data["results"].get("applications", [])
    )

    resp2 = client.get(
        "/api/search?q=systems",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    data2 = resp2.json()
    assert "realms" in data2["results"]
    assert any(
        "Acme" in r["label"] or "acme-systems" in (r.get("sublabel") or "")
        for r in data2["results"]["realms"]
    )

    resp_groups = client.get(
        "/api/search?q=searchable",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert "groups" in resp_groups.json()["results"]

    resp3 = client.get(
        "/api/search?q=key_rotation",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    data3 = resp3.json()
    assert "audit" in data3["results"]

    # Non-admin must never receive admin category keys even when q matches.
    resp4 = client.get(
        "/api/search?q=key_rotation",
        headers={**USER_HEADERS, "Accept": "application/json"},
    )
    results4 = resp4.json()["results"]
    for forbidden in ADMIN_CATEGORY_KEYS:
        assert forbidden not in results4


@respx.mock
def test_global_search_admin_users_fuzzy(client, db_session):
    realm = _realm(db_session)
    assert realm.groups_sync_enabled

    token_url = f"{realm.issuer_url}/protocol/openid-connect/token"
    respx.post(token_url).respond(200, json={"access_token": "t"})
    respx.get(
        "https://kc.example.com/admin/realms/EXAMPLE-CORP/users?search=alicr&max=20"
    ).respond(200, json=[])
    respx.get(
        "https://kc.example.com/admin/realms/EXAMPLE-CORP/users?search=al&max=100"
    ).respond(
        200,
        json=[
            {
                "id": "user-1",
                "username": "alice.martin",
                "email": "alice@example.com",
            }
        ],
    )

    resp = client.get(
        "/api/search?q=alicr",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "users" in data["results"]
    assert data["results"]["users"][0]["label"] == "alice.martin"

    # Same typo must not expose users to a standard account.
    resp_user = client.get(
        "/api/search?q=alicr",
        headers={**USER_HEADERS, "Accept": "application/json"},
    )
    assert "users" not in resp_user.json()["results"]


def test_navbar_global_search_trigger_id(client):
    resp = client.get("/sessions", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    html = resp.text
    assert 'id="global-search-trigger"' in html
    assert 'id="global-search-modal"' in html
    assert html.count('id="app-search"') == 0


def test_portal_apps_keeps_single_app_search_id(client, db_session):
    group = _group(db_session)
    app = _app(db_session, slug="wiki", label="Wiki")
    _grant_app(db_session, app, group)

    resp = client.get("/apps", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert resp.text.count('id="app-search"') == 1
    assert 'id="app-wiki"' in resp.text
    assert 'id="global-search-trigger"' not in resp.text  # portal hide_chrome


def test_search_applications_anchor_uses_app_prefix(client, db_session):
    from app.web.global_search import _search_applications
    from app.web.user_context import UserContext

    group = _group(db_session)
    app = _app(db_session, slug="grafana", label="Grafana", description="Metrics")
    _grant_app(db_session, app, group)
    user = UserContext(
        email="alice@example.com",
        username="alice",
        groups=["team-ops"],
        keycloak_user_id="kc-user-alice",
        realm_slug="default",
        auth_source="headers",
        is_admin=False,
    )
    hits = _search_applications(db_session, user, "grafana")
    assert hits
    assert hits[0]["url"] == "/apps#app-grafana"


def test_admin_finds_app_by_public_fqdn_without_grant(client, db_session):
    """Admins search the full catalogue by FQDN even without a personal grant."""
    _app(
        db_session,
        slug="code-quality",
        label="Code Quality",
        description="Analyse statique",
        public_fqdn="sonarqube.portal.example.com",
        access_mode="subdomain_proxy",
    )
    resp = client.get(
        "/api/search?q=sonarqube",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 200
    apps = resp.json()["results"].get("applications") or []
    assert apps
    assert apps[0]["label"] == "Code Quality"
    assert "sonarqube.portal.example.com" in (apps[0].get("sublabel") or "")
    assert apps[0]["url"] == "/admin/apps/code-quality/edit"


def test_user_finds_granted_app_by_fqdn(client, db_session):
    group = _group(db_session)
    app = _app(
        db_session,
        slug="code-quality",
        label="Code Quality",
        public_fqdn="sonarqube.portal.example.com",
        access_mode="subdomain_proxy",
    )
    _grant_app(db_session, app, group)
    resp = client.get(
        "/api/search?q=sonarqube",
        headers={**USER_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 200
    apps = resp.json()["results"].get("applications") or []
    assert any(r["url"] == "/apps#app-code-quality" for r in apps)


def test_admin_finds_pending_host_subdomain(client, db_session):
    from app.models import PendingHost

    db_session.add(
        PendingHost(
            hostname="sonarqube.portal.example.com",
            status="pending",
            hit_count=3,
            last_uri="/",
        )
    )
    db_session.commit()
    resp = client.get(
        "/api/search?q=sonarqube",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 200
    hosts = resp.json()["results"].get("hosts") or []
    assert any(h["label"] == "sonarqube.portal.example.com" for h in hosts)
    for forbidden in ("hosts",):
        user_resp = client.get(
            "/api/search?q=sonarqube",
            headers={**USER_HEADERS, "Accept": "application/json"},
        )
        assert forbidden not in user_resp.json()["results"]
