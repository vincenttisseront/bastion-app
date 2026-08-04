"""LOT 2 — user directory stats (Keycloak mocked)."""

from __future__ import annotations

import pytest

from app.models import AccessGrant, AuditLog, RealmConfig
from app.rbac.users_stats_service import (
    clear_user_stats_cache,
    connection_anomalies,
    count_privileged_subjects,
    fetch_user_directory_stats,
)
from app.secret_crypto import encrypt_secret
from app.sso_settings import get_settings


ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


@pytest.fixture(autouse=True)
def _clear_stats_cache():
    clear_user_stats_cache()
    yield
    clear_user_stats_cache()


def _realm(db_session) -> RealmConfig:
    s = get_settings()
    realm = RealmConfig(
        slug="portal",
        name="Portal",
        issuer_url="https://kc.example.com/realms/portal",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.test/oauth2/portal/callback",
        oauth2_proxy_port=4180,
        groups_sync_enabled=True,
    )
    db_session.add(realm)
    db_session.commit()
    return realm


@pytest.mark.asyncio
async def test_rbac_users_stats_keycloak_counts(db_session, monkeypatch):
    realm = _realm(db_session)

    async def fake_count(realm_arg, settings, *, enabled=None):
        if enabled is True:
            return 8
        if enabled is False:
            return 2
        return 10

    monkeypatch.setattr(
        "app.rbac.users_stats_service.count_keycloak_users",
        fake_count,
    )

    stats = await fetch_user_directory_stats(db_session, realm, get_settings())
    assert stats.total == 10
    assert stats.active == 8
    assert stats.suspended == 2
    assert stats.error is None


@pytest.mark.asyncio
async def test_rbac_users_stats_keycloak_unavailable(db_session, monkeypatch):
    realm = _realm(db_session)

    async def boom(*args, **kwargs):
        raise RuntimeError("down")

    monkeypatch.setattr(
        "app.rbac.users_stats_service.count_keycloak_users",
        boom,
    )

    stats = await fetch_user_directory_stats(db_session, realm, get_settings())
    assert stats.total is None
    assert stats.error
    assert "Keycloak" in stats.error or "indisponible" in stats.error.lower()


def test_rbac_users_stats_privileged_and_anomalies(db_session):
    db_session.add(
        AccessGrant(
            subject_type="user",
            keycloak_user_id="u1",
            resource_type="system_role",
            system_role="portal_admin",
            access_level="manage",
            granted_by="test",
        )
    )
    db_session.add(
        AuditLog(
            actor="u1",
            action="session_hijack_suspected",
            target="session:1",
            ip_address="1.2.3.4",
        )
    )
    db_session.commit()
    priv, _ = count_privileged_subjects(db_session)
    assert priv >= 1
    anomalies = connection_anomalies(db_session)
    assert anomalies
    assert anomalies[0]["severity"] == "CRITIQUE"


def test_group_distribution_sorts_and_hides_noise(db_session):
    from app.models import RBACGroup
    from app.rbac.users_stats_service import group_distribution

    db_session.add_all(
        [
            RBACGroup(name="zzz-empty", member_count=0),
            RBACGroup(name="alpha-small", member_count=2),
            RBACGroup(name="ARSYSTEMS-Users", member_count=10),
        ]
    )
    db_session.commit()

    dist = group_distribution(db_session)
    assert dist["total_groups"] == 3
    assert dist["with_members"] == 2
    assert dist["empty_groups"] == 1
    assert dist["total_memberships"] == 12
    names = [r["name"] for r in dist["rows"]]
    assert names[0] == "ARSYSTEMS-Users"
    assert names[1] == "alpha-small"
    assert names[2] == "zzz-empty"
    assert dist["rows"][0]["bar_percent"] == 100
    assert dist["rows"][0]["percent"] == 83  # 10/12
    assert dist["rows"][1]["bar_percent"] == 20  # 2/10


def test_rbac_users_stats_page_graceful(client, monkeypatch):
    async def boom(*args, **kwargs):
        raise ValueError("Keycloak offline")

    monkeypatch.setattr(
        "app.rbac.users_stats_service.count_keycloak_users",
        boom,
    )
    resp = client.get("/admin/rbac/users", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Gestion des Utilisateurs" in resp.text
    assert "Gouvernance" in resp.text
