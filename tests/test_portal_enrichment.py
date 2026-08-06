"""Portal enrichment — badges, filters, recent sessions."""

from __future__ import annotations

from app.models import App, AuditLog
from app.web.portal_enrichment import (
    build_apps_sections,
    enrich_tile,
    protocol_filter_key,
    recent_sessions_for_user,
)
from app.web.user_context import UserContext


def test_protocol_filter_and_badges(db_session):
    app = App(
        slug="wiki",
        label="Wiki",
        upstream_url="https://wiki.example.com/",
        access_mode="sso_gate",
        auth_mode="sso",
        last_probe_status="ok",
    )
    db_session.add(app)
    db_session.commit()

    assert protocol_filter_key(app) == "web"
    tile = enrich_tile(
        app,
        {
            "slug": app.slug,
            "label": app.label,
            "can_launch": True,
            "launch_url": app.upstream_url,
        },
    )
    labels = {b["label"] for b in tile["status_badges"]}
    assert "Protégé" in labels
    assert "Opérationnel" in labels


def test_recent_sessions_from_audit(db_session):
    app = App(
        slug="crm",
        label="CRM",
        upstream_url="https://crm.example.com/",
        access_mode="sso_gate",
    )
    db_session.add(app)
    db_session.add(
        AuditLog(
            actor="alice@example.com",
            action="app_launch",
            target="crm",
        )
    )
    db_session.commit()

    user = UserContext(
        email="alice@example.com",
        username="alice",
        groups=[],
        is_admin=False,
        realm_slug="portal",
        auth_source="oidc",
        keycloak_user_id="kc-alice",
    )
    recent = recent_sessions_for_user(
        db_session,
        user,
        apps_by_slug={
            "crm": {
                "id": app.id,
                "slug": "crm",
                "label": "CRM",
                "launch_url": "https://crm.example.com/",
                "can_launch": True,
            }
        },
    )
    assert recent
    assert recent[0]["slug"] == "crm"
    assert recent[0]["label"] == "CRM"


def test_build_apps_sections_favorites_and_applications():
    tiles = [
        {
            "id": 1,
            "slug": "crm",
            "label": "CRM",
            "protocol_filter": "web",
            "can_launch": True,
        },
        {
            "id": 2,
            "slug": "proxy-app",
            "label": "Proxy App",
            "protocol_filter": "proxy",
            "can_launch": True,
        },
        {
            "id": 3,
            "slug": "vault-app",
            "label": "Vault App",
            "protocol_filter": "vault",
            "can_launch": True,
        },
    ]
    sections = build_apps_sections(tiles, favorite_ids=[1])
    assert [s["id"] for s in sections] == ["favorites", "applications"]
    assert sections[0]["label"] == "Accès rapides"
    assert [a["slug"] for a in sections[0]["apps"]] == ["crm"]
    assert sections[0]["is_favorites"] is True
    assert sections[1]["label"] == "Applications"
    assert [a["slug"] for a in sections[1]["apps"]] == [
        "crm",
        "proxy-app",
        "vault-app",
    ]

    empty_fav = build_apps_sections(tiles, favorite_ids=[])
    assert empty_fav[0]["id"] == "favorites"
    assert empty_fav[0]["apps"] == []
    assert empty_fav[1]["id"] == "applications"

    no_empty = build_apps_sections(
        tiles, favorite_ids=[], show_empty_favorites=False
    )
    assert [s["id"] for s in no_empty] == ["applications"]


def test_portal_favorites_add_remove(db_session):
    from app.models import App
    from app.web.portal_favorites import (
        add_favorite,
        list_favorite_app_ids,
        remove_favorite,
    )

    app = App(
        slug="wiki",
        label="Wiki",
        upstream_url="https://wiki.example.com/",
        access_mode="sso_gate",
    )
    db_session.add(app)
    db_session.commit()

    assert list_favorite_app_ids(db_session, "kc-alice") == []
    assert add_favorite(
        db_session,
        keycloak_user_id="kc-alice",
        application_id=app.id,
        actor="alice@example.com",
    )
    assert list_favorite_app_ids(db_session, "kc-alice") == [app.id]
    assert (
        add_favorite(
            db_session,
            keycloak_user_id="kc-alice",
            application_id=app.id,
            actor="alice@example.com",
        )
        is False
    )
    assert remove_favorite(
        db_session,
        keycloak_user_id="kc-alice",
        application_id=app.id,
        actor="alice@example.com",
    )
    assert list_favorite_app_ids(db_session, "kc-alice") == []

