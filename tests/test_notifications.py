"""Admin notification center feed + dismiss."""

from __future__ import annotations

from app.audit import log_action
from app.models import PendingHost, RealmConfig
from app.web.notifications import (
    build_notification_feed,
    dismiss_all_notifications,
    dismiss_notification,
)

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
        hostname="ghost.example.com",
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
        target="ghost.example.com",
        details={"uri": "/admin/", "reason": "unknown_host"},
        ip_address="10.0.0.1",
    )

    feed = build_notification_feed(db_session, user_email="admin@example.com")
    assert feed["count"] >= 2
    ids = {i["id"] for i in feed["items"]}
    assert "pending-hosts" in ids
    assert "access-denied-summary" in ids
    pending = next(i for i in feed["items"] if i["id"] == "pending-hosts")
    assert pending["href"].startswith("/admin/pending-hosts")
    assert "ghost.example.com" in pending["body"]
    assert pending.get("fingerprint")


def test_dismiss_hides_until_fingerprint_changes(db_session):
    db_session.add(
        PendingHost(hostname="ghost.example.com", status="pending", hit_count=1)
    )
    db_session.commit()
    feed = build_notification_feed(db_session, user_email="admin@example.com")
    pending = next(i for i in feed["items"] if i["id"] == "pending-hosts")
    assert feed["count"] >= 1

    dismiss_notification(
        db_session,
        user_email="admin@example.com",
        item_id=pending["id"],
        fingerprint=pending["fingerprint"],
        actor="admin@example.com",
    )
    feed2 = build_notification_feed(db_session, user_email="admin@example.com")
    assert not any(i["id"] == "pending-hosts" for i in feed2["items"])
    assert feed2["count"] == 0

    # Hit-count / last_seen bumps must NOT revive a dismissed aggregate.
    row = db_session.query(PendingHost).filter_by(hostname="ghost.example.com").one()
    row.hit_count = 99
    from app.models import utcnow

    row.last_seen_at = utcnow()
    db_session.commit()
    feed3 = build_notification_feed(db_session, user_email="admin@example.com")
    assert not any(i["id"] == "pending-hosts" for i in feed3["items"])

    # A new hostname changes the set fingerprint → notification returns.
    db_session.add(
        PendingHost(hostname="other.example.com", status="pending", hit_count=1)
    )
    db_session.commit()
    feed4 = build_notification_feed(db_session, user_email="admin@example.com")
    assert any(i["id"] == "pending-hosts" for i in feed4["items"])


def test_denied_summary_watermark_survives_same_window(db_session):
    """Dismissing the 24h summary stays down until a newer denial appears."""
    log_action(
        db_session,
        actor="anonymous",
        action="access_denied_unknown_host",
        target="ghost.example.com",
        details={"uri": "/"},
        ip_address="10.0.0.1",
    )
    feed = build_notification_feed(db_session, user_email="admin@example.com")
    summary = next(i for i in feed["items"] if i["id"] == "access-denied-summary")
    dismiss_notification(
        db_session,
        user_email="admin@example.com",
        item_id=summary["id"],
        fingerprint=summary["fingerprint"],
        actor="admin@example.com",
    )
    # Also dismiss per-event detail rows so only the summary watermark is under test.
    for it in feed["items"]:
        if str(it["id"]).startswith("audit-"):
            dismiss_notification(
                db_session,
                user_email="admin@example.com",
                item_id=it["id"],
                fingerprint=it["fingerprint"],
                actor="admin@example.com",
            )
    feed2 = build_notification_feed(db_session, user_email="admin@example.com")
    assert not any(i["id"] == "access-denied-summary" for i in feed2["items"])

    log_action(
        db_session,
        actor="anonymous",
        action="access_denied_no_app",
        target="ghost.example.com",
        details={"uri": "/x"},
        ip_address="10.0.0.1",
    )
    feed3 = build_notification_feed(db_session, user_email="admin@example.com")
    assert any(i["id"] == "access-denied-summary" for i in feed3["items"])


def test_badge_endpoint(client, db_session):
    db_session.add(
        PendingHost(hostname="teleport.example.fr", status="pending", hit_count=1)
    )
    db_session.commit()
    r = client.get("/api/admin/notifications/badge", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    data = r.json()
    assert data["count"] >= 1
    assert "items" not in data


def test_denied_detail_href_urlencodes_action(db_session):
    """Per-event denied links must keep a well-formed /admin/logs?q=… query."""
    log_action(
        db_session,
        actor="anonymous",
        action="access_denied_no_grant",
        target="app.example.com",
        details={"uri": "/secret", "reason": "no_grant"},
        ip_address="10.0.0.10",
    )
    feed = build_notification_feed(db_session, user_email="admin@example.com")
    detail = next((i for i in feed["items"] if str(i["id"]).startswith("audit-")), None)
    assert detail is not None
    assert detail["href"] == "/admin/logs?q=access_denied_no_grant&status=error"


def test_dismiss_all_api(client, db_session):
    db_session.add(
        PendingHost(hostname="teleport.example.fr", status="pending", hit_count=1)
    )
    db_session.commit()
    r = client.get("/api/admin/notifications", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    assert r.json()["count"] >= 1

    r2 = client.post("/api/admin/notifications/dismiss-all", headers=ADMIN_HEADERS)
    assert r2.status_code == 200
    data = r2.json()
    assert data["ok"] is True
    assert data["count"] == 0
    assert data["items"] == []


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
