"""Realm OIDC admin, validation, connection test, and export tests."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy.orm import Session

from app.admin.export import export_realm_files
from app.admin import oidc_test as oidc_test_module
from app.admin.schemas import RealmConfigCreate
from app.admin.throttling import reset_test_rate_limits
from app.models import RealmConfig
from app.secret_crypto import decrypt_secret, encrypt_secret
from app.sso_settings import Settings

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


def _test_settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )


def _make_realm(
    db: Session,
    *,
    slug: str = "test-realm",
    port: int = 4181,
    last_test_status: str | None = None,
    enabled: bool = False,
) -> RealmConfig:
    settings = _test_settings()
    realm = RealmConfig(
        slug=slug,
        name="Test Realm",
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


@pytest.mark.asyncio
@respx.mock
async def test_oidc_connection_discovery_ok():
    respx.get(DISCOVERY_URL).mock(return_value=Response(200, json=METADATA))
    respx.get(METADATA["jwks_uri"]).mock(return_value=Response(200, json={"keys": [{"kty": "RSA"}]}))
    respx.post(METADATA["token_endpoint"]).mock(
        return_value=Response(200, json={"access_token": "tok"})
    )

    result = await oidc_test_module.test_oidc_connection(ISSUER, "cid", "csecret")

    assert result["status"] == "ok"
    assert any(c["name"] == "discovery" and c["status"] == "ok" for c in result["checks"])


@pytest.mark.asyncio
@respx.mock
async def test_oidc_connection_discovery_404():
    respx.get(DISCOVERY_URL).mock(return_value=Response(404))

    result = await oidc_test_module.test_oidc_connection(ISSUER, "cid", "csecret")

    assert result["status"] == "error"
    assert result["checks"][0]["name"] == "discovery"


@pytest.mark.asyncio
@respx.mock
async def test_oidc_connection_discovery_timeout():
    respx.get(DISCOVERY_URL).mock(side_effect=httpx.ConnectError("timeout"))

    result = await oidc_test_module.test_oidc_connection(ISSUER, "cid", "csecret")

    assert result["status"] == "error"
    assert "Injoignable" in result["checks"][0]["message"]


@pytest.mark.asyncio
@respx.mock
async def test_oidc_connection_incomplete_metadata():
    incomplete = {k: v for k, v in METADATA.items() if k != "jwks_uri"}
    respx.get(DISCOVERY_URL).mock(return_value=Response(200, json=incomplete))

    result = await oidc_test_module.test_oidc_connection(ISSUER, "cid", "csecret")

    assert result["status"] == "error"
    assert result["checks"][-1]["name"] == "metadata"


@pytest.mark.asyncio
@respx.mock
async def test_oidc_connection_issuer_mismatch_warning():
    metadata = dict(METADATA)
    metadata["issuer"] = "https://other.example/realms/test"
    respx.get(DISCOVERY_URL).mock(return_value=Response(200, json=metadata))
    respx.get(metadata["jwks_uri"]).mock(return_value=Response(200, json={"keys": [{"kty": "RSA"}]}))
    respx.post(metadata["token_endpoint"]).mock(
        return_value=Response(400, json={"error": "invalid_grant"})
    )

    result = await oidc_test_module.test_oidc_connection(ISSUER, "cid", "csecret")

    assert result["status"] == "ok"
    issuer_check = next(c for c in result["checks"] if c["name"] == "issuer_match")
    assert issuer_check["status"] == "warning"


@pytest.mark.asyncio
@respx.mock
async def test_oidc_connection_jwks_invalid():
    respx.get(DISCOVERY_URL).mock(return_value=Response(200, json=METADATA))
    respx.get(METADATA["jwks_uri"]).mock(return_value=Response(200, json={"keys": []}))
    respx.post(METADATA["token_endpoint"]).mock(
        return_value=Response(400, json={"error": "invalid_grant"})
    )

    result = await oidc_test_module.test_oidc_connection(ISSUER, "cid", "csecret")

    jwks_check = next(c for c in result["checks"] if c["name"] == "jwks")
    assert jwks_check["status"] == "error"


@pytest.mark.asyncio
@respx.mock
async def test_oidc_connection_invalid_client():
    respx.get(DISCOVERY_URL).mock(return_value=Response(200, json=METADATA))
    respx.get(METADATA["jwks_uri"]).mock(return_value=Response(200, json={"keys": [{"kty": "RSA"}]}))
    respx.post(METADATA["token_endpoint"]).mock(
        return_value=Response(401, json={"error": "invalid_client"})
    )

    result = await oidc_test_module.test_oidc_connection(ISSUER, "cid", "bad-secret")

    cred_check = next(c for c in result["checks"] if c["name"] == "client_credentials")
    assert cred_check["status"] == "error"


@pytest.mark.asyncio
@respx.mock
async def test_oidc_connection_invalid_grant_means_ok_credentials():
    respx.get(DISCOVERY_URL).mock(return_value=Response(200, json=METADATA))
    respx.get(METADATA["jwks_uri"]).mock(return_value=Response(200, json={"keys": [{"kty": "RSA"}]}))
    respx.post(METADATA["token_endpoint"]).mock(
        return_value=Response(400, json={"error": "invalid_grant"})
    )

    result = await oidc_test_module.test_oidc_connection(ISSUER, "cid", "csecret")

    cred_check = next(c for c in result["checks"] if c["name"] == "client_credentials")
    assert cred_check["status"] == "ok"


def test_realm_config_create_validation_rules():
    with pytest.raises(Exception):
        RealmConfigCreate(
            slug="INVALID",
            name="",
            issuer_url="http://insecure",
            client_id="",
            client_secret="",
            oauth2_proxy_port=4000,
            scopes="profile email",
        )


def test_realm_slug_validation_message():
    with pytest.raises(Exception) as exc:
        RealmConfigCreate(
            slug="x",
            name="Name",
            issuer_url=ISSUER,
            client_id="cid",
            client_secret="secret",
            oauth2_proxy_port=4181,
        )
    assert "Slug invalide" in str(exc.value)


def test_enable_blocked_without_successful_test(client: TestClient, db_session: Session):
    realm = _make_realm(db_session, last_test_status=None)

    response = client.post(
        f"/admin/realms/{realm.id}/enable",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )

    assert response.status_code == 400


def test_edit_page_never_exposes_client_secret(client: TestClient, db_session: Session):
    realm = _make_realm(db_session)

    response = client.get(f"/admin/realms/{realm.id}/edit", headers=ADMIN_HEADERS)

    assert response.status_code == 200
    assert "super-secret-value" not in response.text
    assert "••••••••" in response.text


@respx.mock
def test_realm_test_endpoint_persists_result(client: TestClient, db_session: Session):
    realm = _make_realm(db_session)
    respx.get(DISCOVERY_URL).mock(return_value=Response(200, json=METADATA))
    respx.get(METADATA["jwks_uri"]).mock(return_value=Response(200, json={"keys": [{"kty": "RSA"}]}))
    respx.post(METADATA["token_endpoint"]).mock(
        return_value=Response(400, json={"error": "invalid_grant"})
    )

    response = client.post(
        f"/admin/realms/{realm.id}/test",
        headers={**ADMIN_HEADERS, "Content-Type": "application/json"},
        json={},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    db_session.refresh(realm)
    assert realm.last_test_status == "ok"
    assert realm.last_test_detail is not None


def test_export_blocked_without_ok_test(client: TestClient, db_session: Session, tmp_path):
    realm = _make_realm(db_session, last_test_status="error")
    app_settings = _test_settings()
    app_settings.exports_dir = str(tmp_path)

    from app.sso_settings import get_settings

    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: app_settings  # type: ignore[attr-defined]

    response = client.post(
        f"/admin/realms/{realm.id}/export",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )

    assert response.status_code == 409


def test_export_generates_expected_files(client: TestClient, db_session: Session, tmp_path):
    realm = _make_realm(db_session, last_test_status="ok")
    app_settings = _test_settings()
    app_settings.exports_dir = str(tmp_path)

    from app.sso_settings import get_settings

    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: app_settings  # type: ignore[attr-defined]

    response = client.post(
        f"/admin/realms/{realm.id}/export",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )

    assert response.status_code == 200
    proxy_file = tmp_path / f"oauth2-proxy-{realm.slug}.conf"
    nginx_file = tmp_path / "nginx-portal-realms.conf"
    assert proxy_file.is_file()
    assert nginx_file.is_file()
    content = proxy_file.read_text(encoding="utf-8")
    assert 'provider = "oidc"' in content
    assert "super-secret-value" in content
    assert "nginx-portal-realms.conf" in response.json()["paths"]["nginx_realms_conf"]


def test_create_realm_duplicate_slug_returns_field_error(client: TestClient, db_session: Session):
    _make_realm(db_session, slug="dup-realm", port=4182)

    response = client.post(
        "/admin/realms",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        data={
            "slug": "dup-realm",
            "name": "Dup",
            "issuer_url": ISSUER,
            "client_id": "cid",
            "client_secret": "secret",
            "oauth2_proxy_port": 4183,
        },
    )

    assert response.status_code == 400
    assert response.json()["errors"]["slug"] == "Ce slug existe déjà"


def test_create_realm_duplicate_port_returns_field_error(client: TestClient, db_session: Session):
    _make_realm(db_session, slug="realm-a", port=4184)

    response = client.post(
        "/admin/realms",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        data={
            "slug": "realm-b",
            "name": "B",
            "issuer_url": ISSUER,
            "client_id": "cid",
            "client_secret": "secret",
            "oauth2_proxy_port": 4184,
        },
    )

    assert response.status_code == 400
    assert "Port déjà utilisé" in response.json()["errors"]["oauth2_proxy_port"]


def test_delete_blocked_when_enabled(client: TestClient, db_session: Session):
    realm = _make_realm(db_session, enabled=True, last_test_status="ok", port=4185)

    response = client.delete(
        f"/admin/realms/{realm.id}",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )

    assert response.status_code == 400


def test_secret_not_in_export_logs(caplog, db_session: Session, tmp_path):
    settings = _test_settings()
    settings.exports_dir = str(tmp_path)
    realm = _make_realm(db_session, last_test_status="ok", port=4186)

    with caplog.at_level("INFO"):
        export_realm_files(realm, db_session, settings)

    joined = " ".join(caplog.messages)
    assert "super-secret-value" not in joined
    assert decrypt_secret(realm.client_secret_encrypted, settings) == "super-secret-value"
