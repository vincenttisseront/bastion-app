"""Every Keycloak groups sync failure leaves a usable trace.

Application log (realm, client, URL, HTTP status, detected cause; never the
token), audit entry ``rbac.groups.sync_failed`` (Admin → Logs, SIEM), and a
dated ✗ on /admin/realms linking to that entry.
"""

from __future__ import annotations

import base64
import html
import json
import logging

import pytest
import respx

from app.admin.throttling import reset_test_rate_limits
from app.models import AuditLog, RealmConfig
from app.rbac.groups_sync_service import SYNC_FAILED_ACTION, last_sync_failures
from app.rbac.keycloak_admin import (
    KC_ADMIN_API_SCOPE,
    clear_admin_token_cache,
    sync_keycloak_groups,
)
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

ADMIN_HEADERS = {"X-Email": "admin@example.com", "X-Groups": "portal-admins"}
ISSUER = "https://kc.example.com/realms/demo"
TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"
GROUPS_URL = "https://kc.example.com/admin/realms/demo/groups"
_GROUPS_LIST_RE = r"https://kc\.example\.com/admin/realms/demo/groups(?:\?.*)?$"
_GROUPS_CHILDREN_RE = r"https://kc\.example\.com/admin/realms/demo/groups/[^/?]+/children.*"
_GROUP_MEMBERS_RE = r"https://kc\.example\.com/admin/realms/demo/groups/[^/?]+/members.*"
SYNC_CLIENT = "bastion-admin-sync"


def _jwt(**claims) -> str:
    def segment(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{segment({'alg': 'RS256', 'typ': 'JWT'})}.{segment(claims)}.signature"


NO_SCOPE = _jwt(iss=ISSUER, azp=SYNC_CLIENT, scope="profile email")


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
        slug="kc",
        name="Keycloak",
        issuer_url=ISSUER,
        client_id="login-client",
        client_secret_encrypted=encrypt_secret("login-secret", s),
        redirect_uri="https://portal.test/oauth2/kc/callback",
        oauth2_proxy_port=4181,
        enabled=False,
        keycloak_admin_client_id=SYNC_CLIENT,
        keycloak_admin_client_secret_encrypted=encrypt_secret("admin-secret", s),
        groups_sync_enabled=True,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def _mint(token: str) -> None:
    respx.post(TOKEN_URL).respond(
        200, json={"access_token": token, "expires_in": 300}
    )


@pytest.fixture(autouse=True)
def _clean_state():
    reset_test_rate_limits()
    clear_admin_token_cache()
    yield
    clear_admin_token_cache()


@pytest.fixture
def sync_logs():
    """Records of the sync service logger (root handlers are app-managed)."""
    records: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    loggers = [
        logging.getLogger(name)
        for name in ("app.rbac.groups_sync_service", "app.rbac.keycloak_admin")
    ]
    # test_alembic_migration runs migrations/env.py fileConfig(), which disables
    # every logger that already exists (disable_existing_loggers=True).
    saved = [(lg, lg.disabled, lg.level) for lg in loggers]
    for lg in loggers:
        lg.disabled = False
        lg.setLevel(logging.DEBUG)
        lg.addHandler(handler)
    yield records
    for lg, disabled, level in saved:
        lg.removeHandler(handler)
        lg.disabled = disabled
        lg.setLevel(level)


def _post_sync(client, realm, route: str):
    headers = {**ADMIN_HEADERS, "accept": "application/json"}
    if route == "realms":
        from tests.conftest import csrf_token_for

        headers["X-CSRF-Token"] = csrf_token_for(client)
        return client.post(f"/admin/realms/{realm.id}/sync", headers=headers)
    return client.post(f"/admin/rbac/groups/sync/{realm.id}", headers=headers)


@respx.mock
@pytest.mark.parametrize("route", ["realms", "rbac"])
def test_admin_api_401_is_logged_audited_and_shown_dated(client, db_session, sync_logs, route):
    realm = _realm(db_session)
    _mint(NO_SCOPE)
    respx.get(url__regex=_GROUPS_LIST_RE).respond(401)

    resp = _post_sync(client, realm, route)

    assert resp.status_code == 400
    reason = resp.json()["errors"]["_form"]
    assert reason.startswith("Échec lecture groupes Keycloak (HTTP 401) : ")
    assert f"« {KC_ADMIN_API_SCOPE} »" in reason

    # 1. Application log: one structured line, no token.
    lines = [r for r in sync_logs if r.name == "app.rbac.groups_sync_service"]
    assert len(lines) == 1 and lines[0].levelno == logging.WARNING
    line = lines[0].getMessage()
    for fragment in (
        "[BST-RBAC-3001]",
        "realm=kc",
        f"client_id={SYNC_CLIENT}",
        "cause=missing_admin_api_scope",
        "http_status=401",
        f"url={GROUPS_URL} ",
        'token_scope="profile email"',
        f"reason={reason}",
    ):
        assert fragment in line, fragment
    assert NO_SCOPE not in line and "admin-secret" not in line

    # 2. Audit (Admin → Logs, SIEM).
    entry = db_session.query(AuditLog).filter_by(action=SYNC_FAILED_ACTION).one()
    assert entry.target == "kc"
    assert entry.event_code == "BST-RBAC-3001" and entry.severity == "ERROR"
    assert entry.details["cause"] == "missing_admin_api_scope"
    assert entry.details["http_status"] == 401
    assert entry.details["client_id"] == SYNC_CLIENT
    assert entry.details["url"] == GROUPS_URL
    assert entry.details["reason"] == reason

    # 3. /admin/realms: the ✗ is dated and links to that audit entry.
    db_session.refresh(realm)
    assert realm.last_groups_sync_status == "error"
    page = html.unescape(client.get("/admin/realms", headers=ADMIN_HEADERS).text)
    assert f'href="/admin/logs?id={entry.id}" class="realms-sync-fail-link"' in page
    when = entry.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    assert f"Échec sync — {when} — Échec lecture groupes Keycloak (HTTP 401)" in page
    form = html.unescape(
        client.get(f"/admin/realms/{realm.id}/edit", headers=ADMIN_HEADERS).text
    )
    assert f"Dernière sync en erreur ({when}) : Échec lecture groupes Keycloak" in form
    assert f'<a href="/admin/logs?id={entry.id}">Voir l\'entrée d\'audit</a>' in form


@respx.mock
def test_invalid_client_secret_is_traced_with_its_cause(client, db_session, sync_logs):
    realm = _realm(db_session)
    respx.post(TOKEN_URL).respond(401, json={"error": "invalid_client"})

    resp = _post_sync(client, realm, "rbac")

    assert resp.status_code == 400
    entry = db_session.query(AuditLog).filter_by(action=SYNC_FAILED_ACTION).one()
    assert entry.details["cause"] == "invalid_client"
    assert entry.details["url"] == TOKEN_URL
    assert "cause=invalid_client" in sync_logs[-1].getMessage()


def test_unexpected_error_is_logged_with_traceback_and_audited(
    client, db_session, sync_logs, monkeypatch
):
    realm = _realm(db_session)

    async def boom(*_args, **_kwargs):
        raise RuntimeError("database exploded")

    monkeypatch.setattr("app.rbac.groups_sync_service.sync_keycloak_groups", boom)

    resp = _post_sync(client, realm, "rbac")

    assert resp.status_code == 500
    record = [r for r in sync_logs if r.name == "app.rbac.groups_sync_service"][-1]
    assert record.levelno == logging.ERROR and record.exc_info is not None
    entry = db_session.query(AuditLog).filter_by(action=SYNC_FAILED_ACTION).one()
    assert entry.details["cause"] == "server_error"
    assert entry.details["error_type"] == "RuntimeError"


@respx.mock
@pytest.mark.asyncio
async def test_member_refresh_failures_are_counted_not_swallowed(db_session, sync_logs):
    realm = _realm(db_session)
    _mint(_jwt(iss=ISSUER, azp=SYNC_CLIENT, scope=KC_ADMIN_API_SCOPE))
    respx.get(url__regex=_GROUPS_LIST_RE).respond(
        200,
        json=[
            {"id": "g1", "name": "a", "path": "/a", "subGroups": []},
            {"id": "g2", "name": "b", "path": "/b", "subGroups": []},
        ],
    )
    respx.get(url__regex=_GROUPS_CHILDREN_RE).respond(200, json=[])
    respx.get(url__regex=_GROUP_MEMBERS_RE).respond(403)

    result = await sync_keycloak_groups(realm, db_session, _settings())

    assert result["status"] == "ok" and result["imported"] == 2
    assert result["members_failed"] == 2 and result["members_refreshed"] == 0
    assert "view-users" in result["members_error"]
    warnings = [r for r in sync_logs if r.name == "app.rbac.keycloak_admin"]
    assert len(warnings) == 1  # one summary line, not one traceback per group
    assert "failed=2/2" in warnings[0].getMessage()


def test_last_sync_failures_keeps_the_latest_entry_of_realms_in_error(db_session):
    broken = _realm(db_session)
    broken.last_groups_sync_status = "error"
    healthy = RealmConfig(
        slug="ok-realm",
        name="OK",
        issuer_url="https://kc.example.com/realms/ok",
        client_id="c",
        client_secret_encrypted="x",
        redirect_uri="https://portal.test/cb",
        oauth2_proxy_port=4182,
        last_groups_sync_status="ok",
    )
    db_session.add(healthy)
    for target, reason in (("kc", "old"), ("kc", "new"), ("ok-realm", "stale")):
        db_session.add(
            AuditLog(actor="admin", action=SYNC_FAILED_ACTION, target=target,
                     details={"reason": reason})
        )
    db_session.commit()

    found = last_sync_failures(db_session, [broken, healthy])

    assert set(found) == {"kc"}
    assert found["kc"].details["reason"] == "new"
