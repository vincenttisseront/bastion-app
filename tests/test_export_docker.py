"""Export helpers for Docker network mode."""

from sqlalchemy.orm import Session

from app.admin.export import (
    generate_nginx_realms_conf,
    generate_oauth2_proxy_config,
    realm_oauth2_proxy_url,
    write_oauth2_proxy_export,
)
from app.models import RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

ISSUER = "https://keycloak.example/realms/test"


def _realm(db: Session, settings: Settings, slug: str = "clients", port: int = 4182) -> RealmConfig:
    realm = RealmConfig(
        slug=slug,
        name=slug.upper(),
        issuer_url=ISSUER,
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", settings),
        redirect_uri=f"https://portal.example.test/oauth2/{slug}/callback",
        oauth2_proxy_port=port,
        enabled=True,
        last_test_status="ok",
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def test_realm_oauth2_proxy_url_docker(db_session: Session):
    settings = Settings(
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        oauth2_proxy_network_mode="docker",
    )
    realm = _realm(db_session, settings)
    assert realm_oauth2_proxy_url(realm, settings) == "http://oauth2-proxy-clients:4180"


def test_realm_oauth2_proxy_url_docker_core_uses_oauth2_proxy_core(db_session: Session):
    settings = Settings(
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        oauth2_proxy_network_mode="docker",
        oauth2_core_static_enabled=True,
        sso_portal_default_realm_slug="ar-systems",
    )
    realm = _realm(db_session, settings, slug="ar-systems", port=4180)
    assert realm_oauth2_proxy_url(realm, settings) == "http://oauth2-proxy-core:4180"


def test_generate_oauth2_proxy_config_includes_pkce(db_session: Session):
    settings = Settings(
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        oauth2_proxy_network_mode="docker",
        portal_domain="portal.ar-systems.fr",
    )
    realm = _realm(db_session, settings)
    cfg = generate_oauth2_proxy_config(realm, settings)
    assert 'http_address = "0.0.0.0:4180"' in cfg
    assert 'code_challenge_method = "S256"' in cfg
    assert 'insecure_oidc_allow_unverified_email = true' in cfg
    assert 'cookie_expire = "12h"' in cfg
    assert 'cookie_refresh = "1h"' in cfg
    assert 'cookie_samesite = "lax"' in cfg
    assert "cookie_secure = true" in cfg
    assert "cookie_httponly = true" in cfg
    # portal.ar-systems.fr → parent domain for subdomain SSO cookies
    assert 'cookie_domains = [ ".ar-systems.fr" ]' in cfg
    assert 'whitelist_domains = [ ".ar-systems.fr" ]' in cfg


def test_generate_oauth2_proxy_config_skips_cookie_domains_for_short_portal(
    db_session: Session,
):
    settings = Settings(
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        oauth2_proxy_network_mode="docker",
        portal_domain="portal.local",
    )
    realm = _realm(db_session, settings)
    cfg = generate_oauth2_proxy_config(realm, settings)
    assert "cookie_domains" not in cfg
    assert "whitelist_domains" not in cfg


def test_nginx_realms_conf_uses_docker_dns(db_session: Session):
    settings = Settings(
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        oauth2_proxy_network_mode="docker",
        oauth2_core_static_enabled=True,
        sso_portal_default_realm_slug="ar-systems",
    )
    _realm(db_session, settings)
    conf = generate_nginx_realms_conf(db_session, settings)
    # Deferred DNS: variable + rewrite — nginx -t must not require oauth2-proxy up
    assert "set $oauth2_realm_clients oauth2-proxy-clients:4180;" in conf
    assert "proxy_pass http://$oauth2_realm_clients;" in conf
    assert "rewrite ^/oauth2/clients/(.*)$ /oauth2/$1 break;" in conf
    assert "http://oauth2-proxy-clients:4180/oauth2/" not in conf


def test_nginx_realms_conf_loopback_keeps_literal_upstream(db_session: Session):
    settings = Settings(
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        oauth2_proxy_network_mode="loopback",
    )
    _realm(db_session, settings, port=4182)
    conf = generate_nginx_realms_conf(db_session, settings)
    assert "proxy_pass http://127.0.0.1:4182/oauth2/;" in conf
    assert "set $oauth2_realm_" not in conf


def test_write_oauth2_proxy_export_nested(tmp_path, db_session: Session):
    settings = Settings(
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        exports_dir=str(tmp_path),
        oauth2_proxy_network_mode="docker",
    )
    realm = _realm(db_session, settings)
    path = write_oauth2_proxy_export(realm, settings)
    assert path.name == "oauth2-proxy-clients.conf"
    nested = tmp_path / "oauth2" / "clients" / "oauth2-proxy.cfg"
    assert nested.is_file()
    assert 'http_address = "0.0.0.0:4180"' in nested.read_text(encoding="utf-8")
