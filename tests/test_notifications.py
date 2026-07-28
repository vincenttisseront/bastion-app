"""Admin notification center feed."""

from __future__ import annotations

from app.audit import log_action
from app.models import PendingHost, RealmConfig
from app.web.notifications import build_notification_feed

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def test_feed_empty(db_session):
    feed = build_notification_feed(db_session)
    assert feed["count"] == 0
    assert feed["items"] == []
    assert len(feed["shortcuts"]) >= 4
    assert any(s["href"] == "/admin/logs" for s in feed["shortcuts"])


def test_feed_pending_host_and_denied(db_session):
    record = PendingHost(
        hostname="ghost.ar-systems.fr",
        hit_count=3,
        last_uri="/admin/",
        last_client_ip="10.0.0.1",
        status="pending",
    )
    db_session.add(record)
    db_session.commit()

    log_action(
        db_session,
        actor="anonymous",
        action="access_denied_unknown_host",
        target="ghost.ar-systems.fr",
        details={"uri": "/admin/", "reason": "unknown_host"},
        ip_address="10.0.0.1",
    )

    feed = build_notification_feed(db_session)
    assert feed["count"] >= 2
    ids = {i["id"] for i in feed["items"]}
    assert "pending-hosts" in ids
    assert "access-denied-summary" in ids
    pending = next(i for i in feed["items"] if i["id"] == "pending-hosts")
    assert pending["href"].startswith("/admin/pending-hosts")
    assert "ghost.ar-systems.fr" in pending["body"]


def test_feed_realm_oidc_ko(db_session):
    db_session.add(
        RealmConfig(
            slug="broken",
            name="Broken",
            issuer_url="https://kc.example/realms/broken",
            client_id="portal",
            client_secret_encrypted="x",
            redirect_uri="https://portal.test/oauth2/broken/callback",
            oauth2_proxy_port=4182,
            is_default=False,
            enabled=True,
            last_test_status="error",
        )
    )
    db_session.commit()
    feed = build_notification_feed(db_session)
    assert any(i["id"] == "realm-broken" for i in feed["items"])
    assert feed["count"] >= 1


def test_api_notifications_requires_admin(client):
    r = client.get("/api/admin/notifications")
    assert r.status_code in (401, 403)


def test_api_notifications_ok(client, db_session):
    db_session.add(
        PendingHost(hostname="teleport.example.fr", status="pending", hit_count=1)
    )
    db_session.commit()
    r = client.get("/api/admin/notifications", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    data = r.json()
    assert data["count"] >= 1
    assert any(i["id"] == "pending-hosts" for i in data["items"])
    assert any(s["href"] == "/admin/pending-hosts" for s in data["shortcuts"])
