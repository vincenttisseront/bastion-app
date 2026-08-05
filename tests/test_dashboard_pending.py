"""Dashboard pending-queue consolidation."""

from __future__ import annotations

from app.models import (
    AccessRequest,
    BastionAccount,
    PendingHost,
    PendingUser,
    RealmConfig,
)
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings
from app.web.pending_queue_service import (
    build_pending_action_items,
    pending_nav_counts,
)

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )


def _realm(db) -> RealmConfig:
    s = _settings()
    realm = RealmConfig(
        slug="ar-systems",
        name="AR-SYSTEMS",
        issuer_url="https://kc.example.com/realms/AR-SYSTEMS",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.test/cb",
        oauth2_proxy_port=4180,
        enabled=True,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def test_pending_queue_empty(db_session):
    queue = build_pending_action_items(db_session)
    assert queue["total"] == 0
    assert queue["entries"] == []
    assert pending_nav_counts(db_session)["total"] == 0


def test_pending_queue_consolidates_real_sources(db_session):
    realm = _realm(db_session)
    db_session.add(
        PendingHost(hostname="ghost.ar-systems.fr", status="pending", hit_count=2)
    )
    db_session.add(
        PendingHost(
            hostname="discovery-probe-123.ar-systems.fr",
            status="pending",
            hit_count=1,
        )
    )
    db_session.add(
        PendingUser(
            user_email="new@example.com",
            status="pending",
            realm_slug=realm.slug,
            hit_count=1,
        )
    )
    db_session.add(
        AccessRequest(
            username="req",
            email="req@example.com",
            status="pending",
            realm_id=None,
        )
    )
    db_session.add(
        BastionAccount(
            realm_id=realm.id,
            username="stuck",
            email="stuck@example.com",
            status="pending",
            origin="bastion",
            created_by="admin@example.com",
        )
    )
    db_session.commit()

    counts = pending_nav_counts(db_session)
    assert counts["pending_hosts"] == 1  # probe excluded
    assert counts["pending_users"] == 1
    assert counts["access_requests"] == 1
    assert counts["bastion_accounts"] == 1
    assert counts["total"] == 4

    queue = build_pending_action_items(db_session)
    assert queue["total"] == 4
    keys = {i["key"] for i in queue["entries"]}
    assert keys == {
        "pending_hosts",
        "pending_users",
        "access_requests",
        "bastion_accounts",
    }
    by_key = {i["key"]: i for i in queue["entries"]}
    assert by_key["pending_hosts"]["href"] == "/admin/pending-hosts?status=pending"
    assert by_key["pending_users"]["href"] == "/admin/pending-users?status=pending"
    assert by_key["access_requests"]["href"] == "/admin/access-requests?status=pending"
    assert by_key["bastion_accounts"]["href"] == "/admin/rbac/users"


def test_dashboard_shows_pending_hides_ai_and_shortcuts(client, db_session):
    db_session.add(
        PendingHost(hostname="ghost.ar-systems.fr", status="pending", hit_count=1)
    )
    db_session.commit()

    resp = client.get("/dashboard", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Anomalies IA" not in resp.text
    assert "Accès rapides" not in resp.text
    assert "Éléments en attente" in resp.text
    assert 'href="/admin/pending-hosts?status=pending"' in resp.text
    assert 'id="pending-actions"' in resp.text
    # Sidebar dashboard badge
    assert 'data-nav-label="Dashboard"' in resp.text
    assert "nav-badge" in resp.text
