"""ActiveSync mobile access — nginx export + auth_request handler."""

from __future__ import annotations

import base64

from app.bastion.nginx_subdomain_export import generate_subdomain_server_block
from app.models import App, AuditLog
from app.subdomain.activesync_auth import classify_mobile_client, is_activesync_uri
from app.sso_settings import Settings


def _settings(**kwargs) -> Settings:
    base = {
        "portal_domain": "portal.ar-systems.fr",
        "sso_portal_default_realm_slug": "ar-systems",
        "exports_dir": "data/test-exports",
        "vault_portal_internal_token": "test-secret",
    }
    base.update(kwargs)
    return Settings(**base)  # type: ignore[arg-type]


def test_classify_iphone_ua():
    assert classify_mobile_client("Apple-iPhone/1601.405") == "iphone"
    assert classify_mobile_client("Outlook-iOS/...") == "outlook"


def test_is_activesync_uri():
    assert is_activesync_uri("/Microsoft-Server-ActiveSync")
    assert is_activesync_uri("/Microsoft-Server-ActiveSync?Cmd=Sync")
    assert is_activesync_uri("/Autodiscover/Autodiscover.xml")
    assert is_activesync_uri("/autodiscover/autodiscover.xml")
    assert not is_activesync_uri("/web/")


def test_nginx_block_without_flag_has_no_eas_locations():
    app = App(
        slug="mail",
        label="Mail",
        upstream_url="https://10.0.0.9/",
        access_mode="subdomain_proxy",
        public_fqdn="webmail.example.fr",
        allow_activesync=False,
        enabled=True,
    )
    block = generate_subdomain_server_block(app, _settings())
    assert "Microsoft-Server-ActiveSync" not in block
    assert "activesync-auth" not in block


def test_nginx_block_with_flag_has_eas_locations():
    app = App(
        slug="mail",
        label="Mail",
        upstream_url="https://10.0.0.9/",
        access_mode="subdomain_proxy",
        public_fqdn="webmail.example.fr",
        allow_activesync=True,
        enabled=True,
    )
    block = generate_subdomain_server_block(app, _settings())
    assert "Microsoft-Server-ActiveSync" in block
    assert "auth_request /internal/activesync-auth;" in block
    assert "WWW-Authenticate" in block
    assert "proxy_buffering off;" in block
    assert "client_max_body_size 64m;" in block
    assert "proxy_ssl_verify off;" in block
    assert "@portal_redirect_mail" in block  # browser path unchanged
    # Do not rewrite Connection as for WebSockets — breaks EAS Ping keep-alive
    eas_section = block.split("Microsoft-Server-ActiveSync", 1)[1].split("location /", 1)[0]
    assert "proxy_set_header Upgrade" not in eas_section
    assert "proxy_set_header Connection" not in eas_section
    assert "modsecurity off;" in eas_section
    autodiscover = block.split("location ~* ^/(AutoDiscover|autodiscover)/ {", 1)[1]
    autodiscover = autodiscover.split("}", 1)[0]
    assert "modsecurity off;" in autodiscover


def test_activesync_auth_requires_basic_or_sso(client, db_session):
    db_session.add(
        App(
            slug="mail",
            label="Mail",
            upstream_url="https://10.0.0.9/",
            access_mode="subdomain_proxy",
            public_fqdn="webmail.example.fr",
            allow_activesync=True,
            enabled=True,
        )
    )
    db_session.commit()

    denied = client.get(
        "/internal/activesync-auth",
        headers={
            "X-Original-Host": "webmail.example.fr",
            "X-Original-URI": "/Microsoft-Server-ActiveSync",
            "User-Agent": "Apple-iPhone/1601.405",
        },
    )
    assert denied.status_code == 401
    assert "Basic" in denied.headers.get("www-authenticate", "")
    row = (
        db_session.query(AuditLog)
        .filter_by(action="activesync.denied")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert row is not None
    assert row.details.get("client_kind") == "iphone"

    token = base64.b64encode(b"user@example.fr:secret").decode()
    allowed = client.get(
        "/internal/activesync-auth",
        headers={
            "X-Original-Host": "webmail.example.fr",
            "X-Original-URI": "/Microsoft-Server-ActiveSync?Cmd=Sync",
            "User-Agent": "Apple-iPhone/1601.405",
            "Authorization": f"Basic {token}",
        },
    )
    assert allowed.status_code == 200
    assert allowed.headers.get("x-auth-source") == "basic"
    assert allowed.headers.get("x-auth-user") == "user@example.fr"
    ok = (
        db_session.query(AuditLog)
        .filter_by(action="activesync.allowed")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert ok is not None
    assert ok.details.get("auth_source") == "basic"


def test_activesync_auth_disabled_flag(client, db_session):
    db_session.add(
        App(
            slug="mail2",
            label="Mail2",
            upstream_url="https://10.0.0.9/",
            access_mode="subdomain_proxy",
            public_fqdn="webmail2.example.fr",
            allow_activesync=False,
            enabled=True,
        )
    )
    db_session.commit()
    token = base64.b64encode(b"u:p").decode()
    r = client.get(
        "/internal/activesync-auth",
        headers={
            "X-Original-Host": "webmail2.example.fr",
            "X-Original-URI": "/Microsoft-Server-ActiveSync",
            "Authorization": f"Basic {token}",
        },
    )
    assert r.status_code == 401
    assert r.headers.get("x-auth-error") == "activesync_disabled"
