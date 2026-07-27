"""Infrastructure manifest and apply tests."""

import json

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.admin.infrastructure import apply_infrastructure, build_infrastructure_manifest
from app.models import App, RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings, get_settings

ISSUER = "https://keycloak.example/realms/test"
INTERNAL_HEADERS = {"Authorization": "Bearer test-secret"}


def _test_settings(tmp_path) -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        exports_dir=str(tmp_path),
        portal_domain="portal.example.test",
        sso_portal_default_realm_slug="ar-systems",
        oauth2_core_static_enabled=True,
    )


def _make_realm(
    db: Session,
    *,
    slug: str,
    port: int,
    enabled: bool = True,
    is_default: bool = False,
    last_test_status: str = "ok",
) -> RealmConfig:
    settings = Settings(
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    realm = RealmConfig(
        slug=slug,
        name=slug.upper(),
        issuer_url=ISSUER,
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", settings),
        redirect_uri=f"https://portal.example.test/oauth2/{slug}/callback",
        oauth2_proxy_port=port,
        is_default=is_default,
        enabled=enabled,
        last_test_status=last_test_status,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def test_build_manifest_uses_app_not_application_name(db_session: Session, tmp_path):
    settings = _test_settings(tmp_path)
    _make_realm(db_session, slug="ar-systems", port=4180, is_default=True)
    _make_realm(db_session, slug="clients", port=4182)
    db_session.add(
        App(
            slug="wikijs",
            label="Wiki.js",
            upstream_url="https://wikijs.internal/",
            access_mode="sso_gate",
            enabled=True,
        )
    )
    db_session.commit()

    manifest = build_infrastructure_manifest(db_session, settings)

    assert manifest["error"] is None
    assert manifest["partial"] is False
    assert manifest["portal_domain"] == "portal.example.test"
    assert [realm["slug"] for realm in manifest["realms"]] == ["clients"]
    assert manifest["applications"][0]["slug"] == "wikijs"


def test_apply_infrastructure_exports_core_oauth2_cfg_not_nginx(
    db_session: Session, tmp_path
):
    """Core realm: oauth2 cfg from DB (for oauth2-proxy-core); no nginx duplicate location."""
    settings = _test_settings(tmp_path)
    _make_realm(db_session, slug="ar-systems", port=4180, is_default=True)
    _make_realm(db_session, slug="clients", port=4182)

    manifest = apply_infrastructure(db_session, settings)

    assert manifest["partial"] is False
    assert (tmp_path / "oauth2-proxy-clients.conf").is_file()
    assert (tmp_path / "oauth2" / "clients" / "oauth2-proxy.cfg").is_file()
    # Core oauth2 cfg IS exported (source of truth = DB)
    assert (tmp_path / "oauth2-proxy-ar-systems.conf").is_file()
    core_cfg = (tmp_path / "oauth2" / "ar-systems" / "oauth2-proxy.cfg").read_text(
        encoding="utf-8"
    )
    assert 'code_challenge_method = "S256"' in core_cfg
    assert any(f.get("kind") == "oauth2_proxy_core_config" for f in manifest["files"])

    nginx_conf = (tmp_path / "nginx-portal-realms.conf").read_text(encoding="utf-8")
    assert "/oauth2/clients/" in nginx_conf
    assert "/oauth2/ar-systems/" not in nginx_conf

    assert (tmp_path / "nginx-subdomain-apps.conf").is_file()
    assert (tmp_path / "subdomain-apps-inventory.json").is_file()
    assert any(f.get("kind") == "nginx_subdomain_apps_conf" for f in manifest["files"])

    saved = json.loads((tmp_path / "infrastructure-manifest.json").read_text(encoding="utf-8"))
    assert saved["realms"] == manifest["realms"]


def test_apply_skips_untested_realm(db_session: Session, tmp_path):
    settings = _test_settings(tmp_path)
    _make_realm(db_session, slug="clients", port=4182, last_test_status="error")

    manifest = apply_infrastructure(db_session, settings)

    assert manifest["partial"] is False
    assert not (tmp_path / "oauth2-proxy-clients.conf").exists()
    assert manifest["realms"][0]["slug"] == "clients"


def test_internal_apply_endpoint(client: TestClient, db_session: Session, tmp_path):
    settings = _test_settings(tmp_path)
    _make_realm(db_session, slug="clients", port=4182)

    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings  # type: ignore[attr-defined]

    response = client.post(
        "/api/internal/infrastructure/apply",
        headers=INTERNAL_HEADERS,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["portal_domain"] == "portal.example.test"
    assert any(file["kind"] == "oauth2_proxy_config" for file in body["files"])
