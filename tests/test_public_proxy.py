"""public_proxy access mode — catalogue exclusion, validation, nginx export."""

from __future__ import annotations

from types import SimpleNamespace

from app.access_modes import (
    app_launch_url,
    is_user_catalogue_mode,
    normalize_access_mode,
    validate_app_access_fields,
)
from app.admin.export import export_app_catalogue_files, generate_nginx_apps_conf
from app.bastion.nginx_public_proxy_export import (
    generate_public_proxy_apps_nginx,
    generate_public_proxy_server_block,
    iter_public_proxy_apps,
    write_public_proxy_apps_exports,
)
from app.bastion.nginx_subdomain_export import generate_subdomain_apps_nginx
from app.models import AccessGrant, App
from app.rbac.effective_access_service import get_effective_apps_for_user
from app.sso_settings import Settings


def _settings(**kwargs) -> Settings:
    base = {
        "portal_domain": "portal.ar-systems.fr",
        "sso_portal_default_realm_slug": "ar-systems",
        "exports_dir": "data/test-exports",
    }
    base.update(kwargs)
    return Settings(**base)  # type: ignore[arg-type]


def test_normalize_public_proxy():
    assert normalize_access_mode("public_proxy") == "public_proxy"
    assert is_user_catalogue_mode("public_proxy") is False
    assert is_user_catalogue_mode("sso_gate") is True


def test_validate_public_proxy_requires_fqdn():
    errors = validate_app_access_fields("public_proxy", "http://127.0.0.1:8080", None)
    assert "public_fqdn" in errors
    ok = validate_app_access_fields(
        "public_proxy", "http://127.0.0.1:8080", "status.ar-systems.fr"
    )
    assert ok == {}


def test_app_launch_url_public_proxy():
    app = SimpleNamespace(
        access_mode="public_proxy",
        upstream_url="http://172.24.0.120:8080/",
        public_fqdn="status.ar-systems.fr",
        slug="status",
        robotic_driver=None,
    )
    assert app_launch_url(app) == "https://status.ar-systems.fr"


def test_effective_apps_excludes_public_proxy_even_with_grants(db_session):
    pub = App(
        slug="status",
        label="Status",
        upstream_url="http://172.24.0.120:8080/",
        access_mode="public_proxy",
        public_fqdn="status.ar-systems.fr",
        enabled=True,
    )
    wiki = App(
        slug="wiki",
        label="Wiki",
        upstream_url="https://wiki.example.fr/",
        access_mode="sso_gate",
        enabled=True,
    )
    db_session.add_all([pub, wiki])
    db_session.flush()
    db_session.add(
        AccessGrant(
            subject_type="user",
            keycloak_user_id="kc-admin",
            resource_type="application",
            application_id=pub.id,
            access_level="manage",
            granted_by="test",
        )
    )
    db_session.add(
        AccessGrant(
            subject_type="user",
            keycloak_user_id="kc-admin",
            resource_type="application",
            application_id=wiki.id,
            access_level="launch",
            granted_by="test",
        )
    )
    db_session.commit()

    apps = get_effective_apps_for_user(
        db_session, keycloak_user_id="kc-admin", group_names=[]
    )
    assert [e.app.slug for e in apps] == ["wiki"]


def test_public_proxy_nginx_has_no_auth(db_session, tmp_path):
    db_session.add(
        App(
            slug="status",
            label="Status",
            upstream_url="http://172.24.0.120:8080/",
            access_mode="public_proxy",
            public_fqdn="status.ar-systems.fr",
            enabled=True,
        )
    )
    db_session.add(
        App(
            slug="doli",
            label="ERP",
            upstream_url="https://10.0.0.5/",
            access_mode="subdomain_proxy",
            public_fqdn="erp.ar-systems.fr",
            enabled=True,
        )
    )
    db_session.commit()

    block = generate_public_proxy_server_block(
        App(
            slug="status",
            label="Status",
            upstream_url="http://172.24.0.120:8080/",
            access_mode="public_proxy",
            public_fqdn="status.ar-systems.fr",
        )
    )
    assert "server_name status.ar-systems.fr;" in block
    assert "proxy_set_header Upgrade $http_upgrade;" in block
    assert "proxy_set_header Connection $connection_upgrade;" in block
    assert 'proxy_set_header Connection "upgrade";' in block
    assert "proxy_buffering off;" in block
    assert "connect/ws" in block
    for needle in (
        "auth_request",
        "oauth2",
        "internal/subdomain-auth",
        "internal/oauth2-auth",
        "error_page 401",
        "subdomain_auth_common",
    ):
        assert needle not in block

    https_block = generate_public_proxy_server_block(
        App(
            slug="teleport",
            label="Teleport",
            upstream_url="https://10.0.31.103/",
            access_mode="public_proxy",
            public_fqdn="teleport.ar-systems.fr",
        )
    )
    assert "proxy_ssl_verify off;" in https_block
    assert "proxy_ssl_server_name on;" in https_block

    conf = generate_public_proxy_apps_nginx(db_session)
    for needle in (
        "auth_request",
        "oauth2",
        "internal/subdomain-auth",
        "internal/oauth2-auth",
    ):
        assert conf.count(needle) == 0

    # Regression: subdomain_proxy export still has auth
    sub_conf = generate_subdomain_apps_nginx(db_session, _settings())
    assert "auth_request /internal/subdomain-auth;" in sub_conf
    assert "status.ar-systems.fr" not in sub_conf

    # portal-apps snippet points to dedicated file, no location for public_proxy
    portal = generate_nginx_apps_conf(db_session)
    assert "public_proxy" in portal
    assert "location /proxy/status/" not in portal

    settings = _settings(exports_dir=str(tmp_path))
    paths = write_public_proxy_apps_exports(db_session, settings)
    written = (tmp_path / "nginx-public-proxy-apps.conf").read_text(encoding="utf-8")
    assert written.count("auth_request") == 0
    assert "nginx_public_proxy_apps_conf" in paths

    all_paths = export_app_catalogue_files(db_session, settings)
    assert "nginx_public_proxy_apps_conf" in all_paths
    assert "nginx_subdomain_apps_conf" in all_paths


def test_iter_public_proxy_apps_filters(db_session):
    db_session.add_all(
        [
            App(
                slug="wiki",
                label="Wiki",
                upstream_url="https://wiki.example/",
                access_mode="sso_gate",
                enabled=True,
            ),
            App(
                slug="status",
                label="Status",
                upstream_url="http://10.0.0.1/",
                access_mode="public_proxy",
                public_fqdn="status.example.fr",
                enabled=True,
            ),
            App(
                slug="off",
                label="Off",
                upstream_url="http://10.0.0.2/",
                access_mode="public_proxy",
                public_fqdn="off.example.fr",
                enabled=False,
            ),
        ]
    )
    db_session.commit()
    assert [a.slug for a in iter_public_proxy_apps(db_session)] == ["status"]
