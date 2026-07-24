"""Portal enrichment — badges, filters, recent sessions."""

from __future__ import annotations

from app.models import App, AuditLog
from app.web.portal_enrichment import (
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
