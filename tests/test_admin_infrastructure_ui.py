"""Admin Infrastructure UI — page and apply button."""

from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.sso_settings import Settings, get_settings
from app.secret_crypto import encrypt_secret
from app.models import RealmConfig
from tests.test_dependencies import ADMIN_HEADERS, USER_HEADERS

ISSUER = "https://keycloak.example/realms/test"


def _test_settings(tmp_path) -> Settings:
    data = tmp_path / "data"
    exports = data / "exports"
    exports.mkdir(parents=True)
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        exports_dir=str(exports),
        portal_data_dir=str(data),
        portal_domain="portal.example.test",
        sso_portal_default_realm_slug="ar-systems",
        oauth2_core_static_enabled=True,
    )


def _make_realm(db: Session, *, slug: str, port: int) -> RealmConfig:
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
        is_default=slug == "ar-systems",
        enabled=True,
        last_test_status="ok",
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def test_infrastructure_page_requires_admin(client: TestClient):
    resp = client.get("/admin/infrastructure", headers=USER_HEADERS, follow_redirects=False)
    assert resp.status_code in (302, 303, 403)


def test_infrastructure_page_renders_for_admin(
    client: TestClient, db_session: Session, tmp_path
):
    settings = _test_settings(tmp_path)
    _make_realm(db_session, slug="ar-systems", port=4180)
    _make_realm(db_session, slug="clients", port=4182)

    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings  # type: ignore[attr-defined]

    resp = client.get("/admin/infrastructure", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Appliquer l'infrastructure" in resp.text
    assert "portal.example.test" in resp.text
    assert "Statut d'application" in resp.text
    assert "oauth2-proxy" in resp.text


def test_infrastructure_apply_redirects_to_wait_page(
    client: TestClient, db_session: Session, tmp_path
):
    settings = _test_settings(tmp_path)
    _make_realm(db_session, slug="clients", port=4182)

    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings  # type: ignore[attr-defined]

    resp = client.post(
        "/admin/infrastructure/apply",
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("/admin/infrastructure/apply-wait")

    exports = Path(settings.exports_dir)
    data = Path(settings.portal_data_dir)
    assert (exports / "infrastructure-manifest.json").is_file()
    assert (data / "apply-infra.request").is_file()
    assert (data / "apply-infra.status").read_text(encoding="utf-8").startswith("pending")

    page = client.get(location, headers=ADMIN_HEADERS, follow_redirects=False)
    assert page.status_code == 200
    assert "Application sur l’hôte en cours" in page.text
    assert "Export OK" in page.text
