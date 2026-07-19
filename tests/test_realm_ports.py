"""Port allocation, OS bind check, rate-limit, and delete purge for realms."""

from __future__ import annotations

from unittest.mock import patch

import pytest
import respx
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy.orm import Session

from app.admin.export import (
    SYSTEMD_PURGE_LIST_NAME,
    export_realm_files,
    oauth2_proxy_systemd_unit_name,
)
from app.admin.ports import get_next_available_port
from app.admin.ports import test_port_available as check_port_available
from app.admin.throttling import reset_test_rate_limits
from app.models import AuditLog, RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings, get_settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}

ISSUER = "https://keycloak.example/realms/test"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
METADATA = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
    "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
    "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
}


def _settings(**overrides) -> Settings:
    base = dict(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
        oauth2_core_static_enabled=False,
    )
    base.update(overrides)
    return Settings(**base)


def _make_realm(
    db: Session,
    *,
    slug: str = "test-realm",
    port: int = 4181,
    last_test_status: str | None = "ok",
    enabled: bool = False,
) -> RealmConfig:
    settings = _settings()
    realm = RealmConfig(
        slug=slug,
        name=f"Realm {slug}",
        issuer_url=ISSUER,
        client_id="portal-client",
        client_secret_encrypted=encrypt_secret("super-secret-value", settings),
        redirect_uri=f"https://portal.test/oauth2/{slug}/callback",
        oauth2_proxy_port=port,
        is_default=False,
        enabled=enabled,
        last_test_status=last_test_status,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


@pytest.fixture(autouse=True)
def _reset_throttle():
    reset_test_rate_limits()
    yield
    reset_test_rate_limits()


def test_get_next_available_port_skips_used_ports(db_session: Session):
    settings = _settings()
    _make_realm(db_session, slug="a", port=4180)
    _make_realm(db_session, slug="b", port=4181)
    _make_realm(db_session, slug="c", port=4183)

    assert get_next_available_port(db_session, settings) == 4182


def test_get_next_available_port_freed_after_delete(db_session: Session):
    settings = _settings()
    realm = _make_realm(db_session, slug="temp", port=4180)
    assert get_next_available_port(db_session, settings) == 4181

    db_session.delete(realm)
    db_session.commit()

    assert get_next_available_port(db_session, settings) == 4180


def test_check_port_available_free_and_occupied():
    with patch("app.admin.ports.socket.socket") as sock_cls:
        sock = sock_cls.return_value
        sock.bind.side_effect = OSError("Address already in use")
        busy = check_port_available(4242)
        assert busy["available"] is False
        assert "4242" in str(busy["message"])

    with patch("app.admin.ports.socket.socket") as sock_cls:
        sock = sock_cls.return_value
        sock.bind.return_value = None
        free = check_port_available(4242)
        assert free["available"] is True
        assert "4242" in str(free["message"])


def test_create_integrity_error_proposes_new_port(
    client: TestClient, db_session: Session, monkeypatch
):
    _make_realm(db_session, slug="holder", port=4190)
    monkeypatch.setattr("app.admin.realms._check_port_unique", lambda *a, **k: None)

    response = client.post(
        "/admin/realms",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        data={
            "slug": "racer",
            "name": "Racer",
            "issuer_url": ISSUER,
            "client_id": "cid",
            "client_secret": "secret",
            "oauth2_proxy_port": 4190,
        },
    )

    assert response.status_code == 400
    err = response.json()["errors"]["oauth2_proxy_port"]
    assert "vient d'être pris" in err

    audits = (
        db_session.query(AuditLog)
        .filter_by(action="realm.port_reallocated", target="racer")
        .all()
    )
    assert len(audits) == 1
    details = audits[0].details or {}
    assert details.get("oauth2_proxy_port_requested") == 4190
    proposed = details.get("oauth2_proxy_port")
    assert proposed != 4190
    assert proposed == 4180  # first free in pool
    assert str(proposed) in err
    joined = str(details)
    assert "super-secret-value" not in joined
    assert "client_secret" not in joined


def test_create_logs_allocated_port_without_secret(client: TestClient, db_session: Session):
    response = client.post(
        "/admin/realms",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        data={
            "slug": "logged-realm",
            "name": "Logged",
            "issuer_url": ISSUER,
            "client_id": "cid",
            "client_secret": "plain-secret-never-in-audit",
            "oauth2_proxy_port": 4195,
        },
    )
    assert response.status_code == 200

    entry = (
        db_session.query(AuditLog)
        .filter_by(action="realm.created", target="logged-realm")
        .one()
    )
    assert entry.details == {"oauth2_proxy_port": 4195}
    assert "plain-secret-never-in-audit" not in str(entry.details)


@respx.mock
def test_realm_test_endpoint_rate_limited(client: TestClient, db_session: Session):
    realm = _make_realm(db_session, slug="throttled", port=4192)
    respx.get(DISCOVERY_URL).mock(return_value=Response(200, json=METADATA))
    respx.get(METADATA["jwks_uri"]).mock(
        return_value=Response(200, json={"keys": [{"kty": "RSA"}]})
    )
    respx.post(METADATA["token_endpoint"]).mock(
        return_value=Response(400, json={"error": "invalid_grant"})
    )

    headers = {**ADMIN_HEADERS, "Content-Type": "application/json"}
    first = client.post(f"/admin/realms/{realm.id}/test", headers=headers, json={})
    second = client.post(f"/admin/realms/{realm.id}/test", headers=headers, json={})

    assert first.status_code == 200
    assert second.status_code == 429
    assert "Trop de tests" in second.json()["errors"]["_form"]


def test_delete_purges_nginx_and_systemd_marker(
    client: TestClient, db_session: Session, tmp_path
):
    keep = _make_realm(db_session, slug="keep-me", port=4193, enabled=True)
    doomed = _make_realm(db_session, slug="doomed", port=4194, enabled=True)

    app_settings = _settings(exports_dir=str(tmp_path))
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: app_settings  # type: ignore[attr-defined]

    export_realm_files(keep, db_session, app_settings)
    export_realm_files(doomed, db_session, app_settings)
    nginx_before = (tmp_path / "nginx-portal-realms.conf").read_text(encoding="utf-8")
    assert "/oauth2/doomed/" in nginx_before
    assert "/oauth2/keep-me/" in nginx_before

    doomed.enabled = False
    db_session.commit()

    response = client.delete(
        f"/admin/realms/{doomed.id}",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert response.status_code == 200

    nginx_after = (tmp_path / "nginx-portal-realms.conf").read_text(encoding="utf-8")
    assert "/oauth2/doomed/" not in nginx_after
    assert "/oauth2/keep-me/" in nginx_after

    purge_list = tmp_path / "systemd" / SYSTEMD_PURGE_LIST_NAME
    assert purge_list.is_file()
    purge_text = purge_list.read_text(encoding="utf-8")
    assert oauth2_proxy_systemd_unit_name("doomed") in purge_text

    entry = (
        db_session.query(AuditLog)
        .filter_by(action="realm.deleted", target="doomed")
        .one()
    )
    assert entry.details["oauth2_proxy_port"] == 4194
    assert "super-secret-value" not in str(entry.details)

    used_ports = {p for (p,) in db_session.query(RealmConfig.oauth2_proxy_port).all()}
    assert 4194 not in used_ports
