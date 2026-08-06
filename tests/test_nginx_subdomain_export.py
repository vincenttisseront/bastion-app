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
    assert 'set $app_upstream "https://10.0.0.5";' in block
    assert "rewrite ^/(.*)$ /dolibarr/$1 break;" not in block
    assert "rd=https://$host$request_uri" in block
    assert "bastion_sub=1" in block
    assert "ae=$bastion_auth_err" in block
    assert 'set $bastion_vhost_fqdn "dolibarr.ar-systems.fr";' in block
    assert "/auth/login?rd=https://" in block
    assert "/oauth2/" not in block.split("@portal_redirect")[1]
    assert "?rd=$request_uri;" not in block
    assert "proxy_set_header Cookie $http_cookie;" in block
    assert "$cookie_CrushAuth" not in block
    main = block.split("location / {", 1)[1]
    # Snapshot + auth in same location / (no 418 gate / if{} / map cycle).
    assert "set $bastion_pass_session $cookie_bastion_session;" in main
    assert "set $bastion_pass_cookie $http_cookie;" in main
    assert "return 418;" not in main
    assert "bastion_auth_gate_" not in block
    assert 'if ($bastion_fresh_session != "") {' not in main
    assert "set $bastion_pass_session $bastion_pick_session;" not in main
    assert (
        'set $bastion_auth_cookie '
        '"bastion_session=$bastion_pass_session; $bastion_pass_cookie";'
    ) in main
    assert main.index("set $bastion_auth_cookie") < main.index(
        "auth_request /internal/subdomain-auth"
    )
    assert "set $bastion_auth_cookie $http_cookie;" not in main
    assert "auth_request /internal/subdomain-auth;" in main
    assert "auth_request_set $bastion_auth_err" in main
    assert main.index("auth_request /internal/subdomain-auth") < main.index(
        "auth_request_set $bastion_auth_err"
    )
    # Location-/ capture only — server{} re-set wipes on auth subrequest (ck=72).
    before_main = block.split("location / {", 1)[0]
    assert "set $bastion_pass_cookie $http_cookie;" not in before_main
    assert "set $bastion_pass_session $cookie_bastion_session;" not in before_main
    assert "set $bastion_auth_cookie" not in before_main
    assert "proxy_intercept_errors off;" in main
    # Upload limit + streaming — nginx defaults are 1m / buffering on: large
    # POST bodies would 413 or spool to client_body_temp before the upstream.
    assert "client_max_body_size 64m;" in block
    assert "proxy_buffering off;" in main
    assert "proxy_request_buffering off;" in main


def test_generate_crushftp_block_filters_portal_cookies():
    """CrushFTP Cookie: CrushAuth + currentAuth only — never bastion_session JWT.

    bastion_session / oauth2 cookies cause CrushFTP 502 or Absolute IP login
    redirects. Auth isolation is @app_upstream_* (filter not in location /).
    """
    app = App(
        slug="transfer",
        label="Transfer",
        upstream_url="https://172.24.0.106/",
        access_mode="subdomain_proxy",
        public_fqdn="transfer.ar-systems.fr",
        realm_slug="ar-systems",
        robotic_driver="crushftp",
        enabled=True,
    )
    block = generate_subdomain_server_block(app, _settings())
    assert "CrushAuth=$cookie_CrushAuth" in block
    assert "currentAuth=$cookie_currentAuth" in block
    assert "bastion_session=$cookie_bastion_session" not in block
    assert "set $bastion_upstream_cookie" in block
    assert "proxy_set_header Cookie $bastion_upstream_cookie;" in block
    assert "proxy_redirect http://172.24.0.106/" in block
    assert "proxy_redirect https://172.24.0.106/" in block
    # Forwarded-IP headers must be BLANKED (not just omitted) toward CrushFTP:
    # the DMZ edge proxy adds X-Forwarded-For: <client-ip> and nginx forwards
    # inbound headers unchanged unless overridden. CrushFTP trusts XFF, while
    # the robotic login (direct, no XFF) registers the docker host IP →
    # "session invalidated due to IP change" → 302 login.html + cookie wipe.
    # Empty value makes nginx drop the header so CrushFTP always sees the
    # TCP source IP, identical for both paths.
    # 2G uploads (legacy hand-written transfer vhost) + streaming both ways —
    # without them the transfer stalls: CrushFTP.log only shows the
    # getSessionTimeout keepalives while nginx 413s / spools the upload.
    assert "client_max_body_size 2G;" in block
    named_block = block.split("location @app_upstream_transfer {", 1)[1]
    assert "proxy_buffering off;" in named_block
    assert "proxy_request_buffering off;" in named_block
    assert 'proxy_set_header X-Real-IP "";' in named_block
    assert 'proxy_set_header X-Forwarded-For "";' in named_block
    assert "proxy_set_header X-Real-IP $remote_addr" not in named_block
    assert (
        "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for" not in named_block
    )
    assert "location = /WebInterface/new-ui/" in block
    assert "return 302 /WebInterface/new-ui/index.html;" in block
    assert "proxy_hide_header WWW-Authenticate;" in block
    # Auth gate must NOT contain CrushFTP Cookie filter (inherits into auth_request).
    main = block.split("location / {", 1)[1].split("location @app_upstream_transfer", 1)[0]
    assert "CrushAuth=$cookie_CrushAuth" not in main
    assert "proxy_set_header Cookie $bastion_upstream_cookie;" not in main
    assert "return 418;" not in main
    assert "bastion_auth_gate_" not in block
    assert "auth_request /internal/subdomain-auth;" in main
    assert "try_files /nonexistent @app_upstream_transfer;" in main
    # Filter lives only in the named upstream location (after auth).
    named = block.split("location @app_upstream_transfer {", 1)[1]
    assert "set $bastion_upstream_cookie" in named
    assert "proxy_set_header Cookie $bastion_upstream_cookie;" in named
    assert "proxy_set_header Cookie $http_cookie;" not in named
    # Auth gets client jar via location-/ capture (not server{} — wipe on auth).
    before_main = block.split("location / {", 1)[0]
    assert "set $bastion_pass_cookie $http_cookie;" not in before_main
    assert "set $bastion_auth_cookie" not in before_main
    assert "CrushAuth=$cookie_CrushAuth" not in before_main
    main_gate = block.split("location / {", 1)[1].split("location @app_upstream_transfer", 1)[0]
    assert "set $bastion_pass_session $cookie_bastion_session;" in main_gate
    assert "set $bastion_pass_cookie $http_cookie;" in main_gate
    assert "set $bastion_pass_session $bastion_pick_session;" not in main_gate
    assert 'if ($bastion_fresh_session != "") {' not in main_gate
    assert (
        'set $bastion_auth_cookie '
        '"bastion_session=$bastion_pass_session; $bastion_pass_cookie";'
    ) in main_gate
    assert "CrushAuth=$cookie_CrushAuth" not in main_gate
    assert "proxy_set_header Cookie $bastion_upstream_cookie;" not in main_gate


def test_generate_server_block_strips_web_path():
    """Grommunio/Teleport: /web in upstream_url must not become proxy_pass URI."""
    app = App(
        slug="grommunio",
        label="Mail",
        upstream_url="https://10.0.0.50/web/",
        access_mode="subdomain_proxy",
        public_fqdn="webmail.ar-systems.fr",
        realm_slug="ar-systems",
        enabled=True,
    )
    block = generate_subdomain_server_block(app, _settings())
    assert 'set $app_upstream "https://10.0.0.50";' in block
    assert 'set $app_upstream "https://10.0.0.50/web"' not in block
    assert "rewrite " not in block
    assert "rd=https://$host$request_uri" in block
    assert "bastion_sub=1" in block
    assert "/auth/login?rd=https://" in block


def test_generate_crushftp_auth_include_keeps_full_cookie_path():
    """Upstream CrushAuth filter must not imply auth_request drops bastion_session."""
    app = App(
        slug="transfer",
        label="Transfer",
        upstream_url="https://172.24.0.106/",
        access_mode="subdomain_proxy",
        public_fqdn="transfer.ar-systems.fr",
        realm_slug="ar-systems",
        robotic_driver="crushftp",
        enabled=True,
    )
    block = generate_subdomain_server_block(app, _settings())
    assert "include /etc/nginx/snippets/subdomain_auth_common.conf;" in block
    assert "/auth/login?rd=https://" in block
    # CrushFTP filter is only inside @app_upstream_* — not server-level / auth gate.
    before_main = block.split("location / {", 1)[0]
    assert "CrushAuth=$cookie_CrushAuth" not in before_main
    # No server{} Cookie capture — that rewrite re-runs on auth and wipes (ck=72).
    assert "set $bastion_pass_cookie $http_cookie;" not in before_main
    assert "set $bastion_auth_cookie" not in before_main
    main = block.split("location / {", 1)[1].split("location @app_upstream_transfer", 1)[0]
    assert "set $bastion_pass_session $cookie_bastion_session;" in main
    assert "set $bastion_pass_cookie $http_cookie;" in main
    assert "return 418;" not in main
    assert "bastion_auth_gate_" not in block
    assert "set $bastion_pass_session $bastion_pick_session;" not in main
    assert 'if ($bastion_fresh_session != "") {' not in main
    assert (
        'set $bastion_auth_cookie '
        '"bastion_session=$bastion_pass_session; $bastion_pass_cookie";'
    ) in main
    assert "set $bastion_auth_cookie $http_cookie;" not in main
    assert "set $bastion_upstream_cookie" not in main
    assert "auth_request_set $bastion_auth_err" in main
    assert "auth_request_set $auth_user" in main
    assert "auth_request_set $auth_email" in main
    assert "auth_request_set $auth_preferred" in main
    assert "proxy_intercept_errors off;" in main
    assert "try_files /nonexistent @app_upstream_transfer;" in main
    named = block.split("location @app_upstream_transfer {", 1)[1]
    assert "set $bastion_upstream_cookie" in named
    assert "proxy_set_header X-Auth-User $auth_user;" in named
    assert "proxy_set_header X-Forwarded-Email $auth_email;" in named
    assert "proxy_set_header X-Forwarded-User $auth_display;" in named


def test_generate_non_crushftp_forwards_trusted_identity_headers():
    """SSO subdomain apps get email/name headers for upstream trusted-header auth."""
    app = App(
        slug="open-webui",
        label="Open WebUI",
        upstream_url="https://10.0.31.112/",
        access_mode="subdomain_proxy",
        public_fqdn="open-webui.ar-systems.fr",
        realm_slug="ar-systems",
        auth_mode="sso",
        enabled=True,
    )
    block = generate_subdomain_server_block(app, _settings())
    assert "auth_request_set $auth_email $upstream_http_x_auth_request_email;" in block
    assert "proxy_set_header X-Forwarded-Email $auth_email;" in block
    assert "proxy_set_header X-Forwarded-User $auth_display;" in block
    assert "proxy_set_header X-Auth-Email $auth_email;" in block
    assert "proxy_set_header X-Auth-Source $auth_source;" in block


def test_allow_identity_headers_email_fallback_from_preferred():
    from app.subdomain.subdomain_auth import _allow_identity_headers

    headers = _allow_identity_headers(
        app_slug="open-webui",
        auth_source="oidc",
        preferred="alice@example.com",
        groups=["ops"],
    )
    assert headers["X-Auth-Email"] == "alice@example.com"
    assert headers["X-Auth-Request-Email"] == "alice@example.com"
    assert headers["X-Auth-Display-Name"] == "alice@example.com"
    assert "ops" in headers["X-Auth-Groups"]


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
