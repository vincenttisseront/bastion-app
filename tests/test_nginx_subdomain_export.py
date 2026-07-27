"""Subdomain nginx export from App DB (front bastion-nginx + hop)."""

from __future__ import annotations

import json
from pathlib import Path

from app.bastion.nginx_subdomain_export import (
    generate_subdomain_apps_inventory,
    generate_subdomain_apps_nginx,
    generate_subdomain_server_block,
    iter_subdomain_proxy_apps,
    write_subdomain_apps_exports,
)
from app.models import App
from app.sso_settings import Settings


def _settings(**kwargs) -> Settings:
    base = {
        "portal_domain": "portal.ar-systems.fr",
        "sso_portal_default_realm_slug": "ar-systems",
        "exports_dir": "data/test-exports",
    }
    base.update(kwargs)
    return Settings(**base)  # type: ignore[arg-type]


def test_iter_subdomain_proxy_apps_filters(db_session):
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
                slug="doli",
                label="ERP",
                upstream_url="https://10.0.0.5/",
                access_mode="subdomain_proxy",
                public_fqdn="erp.ar-systems.fr",
                enabled=True,
            ),
            App(
                slug="off",
                label="Off",
                upstream_url="https://10.0.0.6/",
                access_mode="subdomain_proxy",
                public_fqdn="off.ar-systems.fr",
                enabled=False,
            ),
        ]
    )
    db_session.commit()
    apps = iter_subdomain_proxy_apps(db_session)
    assert [a.slug for a in apps] == ["doli"]


def test_generate_server_block_includes_hop_not_internal():
    app = App(
        slug="doli",
        label="ERP",
        upstream_url="https://10.0.0.5/dolibarr/",
        access_mode="subdomain_proxy",
        public_fqdn="dolibarr.ar-systems.fr",
        realm_slug="ar-systems",
        enabled=True,
    )
    block = generate_subdomain_server_block(app, _settings())
    assert "server_name dolibarr.ar-systems.fr;" in block
    assert "location = /.bastion/session-cookies" in block
    assert "auth_request off;" in block
    assert "internal;" not in block.split("session-cookies")[1].split("location /")[0]
    assert "session-cookie-hop" in block
    assert "proxy_set_header Host portal.ar-systems.fr;" in block
    assert "auth_request /internal/subdomain-auth;" in block
    assert 'set $app_upstream "https://10.0.0.5/dolibarr";' in block


def test_generate_conf_and_inventory(db_session, tmp_path):
    db_session.add(
        App(
            slug="mail",
            label="Mail",
            upstream_url="https://mail-backend:8443/",
            access_mode="subdomain_proxy",
            public_fqdn="webmail.ar-systems.fr",
            enabled=True,
        )
    )
    db_session.commit()
    settings = _settings(exports_dir=str(tmp_path))
    conf = generate_subdomain_apps_nginx(db_session, settings)
    assert "webmail.ar-systems.fr" in conf
    assert "/.bastion/session-cookies" in conf
    inv = generate_subdomain_apps_inventory(db_session, settings)
    assert inv["applications"][0]["slug"] == "mail"
    assert inv["applications"][0]["session_cookie_hop"] is True

    paths = write_subdomain_apps_exports(db_session, settings)
    assert Path(paths["nginx_subdomain_apps_conf"]).is_file()
    data = json.loads(Path(paths["subdomain_apps_inventory"]).read_text(encoding="utf-8"))
    assert len(data["applications"]) == 1
    assert (tmp_path / "nginx-subdomain-apps" / "mail.conf").is_file()

    # prune stale
    stale = tmp_path / "nginx-subdomain-apps" / "gone.conf"
    stale.write_text("# stale", encoding="utf-8")
    write_subdomain_apps_exports(db_session, settings)
    assert not stale.exists()
