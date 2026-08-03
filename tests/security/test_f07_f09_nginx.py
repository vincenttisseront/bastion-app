"""F-07: Nginx templates must mark all portal /internal/* auth handlers as internal."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _assert_internal_locations(text: str, path: str) -> None:
    for name in (
        "/internal/oauth2-auth",
        "/internal/portal-rfc1918-bypass-auth",
        "/internal/subdomain-auth",
    ):
        # subdomain-auth may live in an included snippet; portal handlers must be in file
        if name == "/internal/subdomain-auth":
            continue
        assert f"location = {name}" in text, f"{path} missing location {name}"
        # Rough: the location block containing the path must include `internal;`
        idx = text.index(f"location = {name}")
        block = text[idx : idx + 200]
        assert "internal;" in block, f"{path}: {name} must be internal"


def test_activesync_auth_snippet_is_internal():
    path = ROOT / "docker/nginx/snippets/activesync_auth_common.conf"
    text = path.read_text(encoding="utf-8")
    assert "location = /internal/activesync-auth" in text
    idx = text.index("location = /internal/activesync-auth")
    assert "internal;" in text[idx : idx + 200]
    assert "Authorization" in text
    parent = (ROOT / "docker/nginx/snippets/subdomain_auth_common.conf").read_text(
        encoding="utf-8"
    )
    assert "activesync_auth_common.conf" in parent
    j2 = (ROOT / "nginx/snippets/subdomain_auth_common.conf.j2").read_text(encoding="utf-8")
    assert "location = /internal/activesync-auth" in j2
    assert "internal;" in j2


def test_docker_portal_unknown_host_location_is_internal():
    path = ROOT / "docker/nginx/templates/vhost_sso_portal.conf.template"
    text = path.read_text(encoding="utf-8")
    assert "location = /internal/unknown-host" in text
    idx = text.index("location = /internal/unknown-host")
    assert "internal;" in text[idx : idx + 200]
    assert "location = /__bastion_unknown_host" in text
    assert "$bastion_unknown_host" in text


def test_docker_portal_vhost_is_default_server_on_8080():
    """Portal must own default_server — conf.d is alphabetical (nginx-*.conf first)."""
    path = ROOT / "docker/nginx/templates/vhost_sso_portal.conf.template"
    text = path.read_text(encoding="utf-8")
    assert "listen 0.0.0.0:8080 default_server;" in text


def test_subdomain_and_public_proxy_exports_are_not_default_server():
    from app.bastion.nginx_public_proxy_export import generate_public_proxy_server_block
    from app.bastion.nginx_subdomain_export import generate_subdomain_server_block
    from app.models import App
    from app.sso_settings import Settings

    sub = generate_subdomain_server_block(
        App(
            slug="doli",
            label="ERP",
            upstream_url="https://10.0.0.5/",
            access_mode="subdomain_proxy",
            public_fqdn="erp.example.fr",
        ),
        Settings(
            portal_domain="portal.example.fr",
            sso_portal_default_realm_slug="ar-systems",
            exports_dir="data/x",
        ),  # type: ignore[arg-type]
    )
    pub = generate_public_proxy_server_block(
        App(
            slug="status",
            label="Status",
            upstream_url="http://10.0.0.1/",
            access_mode="public_proxy",
            public_fqdn="status.example.fr",
        )
    )
    assert "default_server" not in sub
    assert "default_server" not in pub
    assert "listen 0.0.0.0:8080;" in sub
    assert "listen 0.0.0.0:8080;" in pub
    assert "access_log /var/log/nginx/apps/doli.access.log app;" in sub
    assert "error_log  /var/log/nginx/apps/doli.error.log warn;" in sub
    assert "access_log /var/log/nginx/apps/status.access.log app;" in pub
    assert "error_log  /var/log/nginx/apps/status.error.log warn;" in pub
    assert "proxy_set_header Upgrade $http_upgrade;" in pub
    assert "proxy_set_header Connection $connection_upgrade;" in pub


def test_acme_tls_sync_forwards_websocket_headers():
    """:443 → :8080 must re-set Upgrade/Connection or Teleport wss breaks."""
    text = (ROOT / "docker/nginx/sync-acme-tls.sh").read_text(encoding="utf-8")
    assert "proxy_set_header Upgrade" in text
    assert "connection_upgrade" in text
    assert "proxy_read_timeout 3600s" in text
    # Large oauth2 Set-Cookie on callback must not become nginx 500
    assert "proxy_buffer_size 128k" in text
    assert "proxy_buffers 8 128k" in text
    main = (ROOT / "docker/nginx/nginx.conf").read_text(encoding="utf-8")
    assert "map $http_upgrade $connection_upgrade" in main


def test_j2_portal_vhost_internal_handlers():
    path = ROOT / "nginx/vhosts/vhost_sso_portal.conf.j2"
    text = path.read_text(encoding="utf-8")
    _assert_internal_locations(text, str(path))


def test_subdomain_auth_snippet_still_internal():
    path = ROOT / "nginx/snippets/subdomain_auth_common.conf.j2"
    text = path.read_text(encoding="utf-8")
    assert "location = /internal/subdomain-auth" in text
    assert "internal;" in text
    assert "X-Bastion-Session-Cookie" in text
    assert "$bastion_pass_session" in text
    assert "$bastion_auth_cookie" in text
    assert "proxy_pass_request_headers off;" in text
    assert "proxy_set_header Host            $bastion_vhost_fqdn;" in text
    docker = (ROOT / "docker/nginx/snippets/subdomain_auth_common.conf").read_text(
        encoding="utf-8"
    )
    assert "X-Bastion-Session-Cookie" in docker
    assert "X-Bastion-Session-From-Jar" in docker
    # Session headers from parent capture DIRECTLY — not map fallbacks to $http_cookie.
    assert "X-Bastion-Session-Cookie $bastion_pass_session" in docker
    assert "X-Bastion-Session-From-Jar $bastion_session_from_jar" in docker
    assert "proxy_set_header Cookie          $bastion_auth_cookie;" in docker
    assert "proxy_pass_request_headers off;" in docker
    assert "proxy_set_header Host            $bastion_auth_host;" in docker
    assert "$bastion_x_session" not in docker
    assert "$bastion_auth_session" not in docker
    nginx_conf = (ROOT / "docker/nginx/nginx.conf").read_text(encoding="utf-8")
    assert "auth_err=$bastion_auth_err" in nginx_conf
    assert "nginx-subdomain-auth.map.conf" in nginx_conf
    auth_map = (ROOT / "docker/nginx/includes/nginx-subdomain-auth.map.conf").read_text(
        encoding="utf-8"
    )
    assert "$bastion_auth_host" in auth_map
    assert "$bastion_vhost_fqdn" in auth_map
    assert "$bastion_session_from_jar" in auth_map
    assert "$bastion_pass_cookie" in auth_map
    assert "map $http_cookie $bastion_fresh_session" in auth_map
    # No map that falls back auth Cookie/session to filtered $http_cookie.
    assert "map $bastion_pass_cookie $bastion_auth_cookie" not in auth_map
    assert "map $bastion_pass_session $bastion_auth_session" not in auth_map
    assert '""      $http_cookie;' not in auth_map
    assert '""      $cookie_bastion_session;' not in auth_map
    assert "$bastion_session_from_http" not in auth_map
    assert "$bastion_session_from_pass" not in auth_map
    activesync = (
        ROOT / "docker/nginx/snippets/activesync_auth_common.conf"
    ).read_text(encoding="utf-8")
    assert "proxy_pass_request_headers off;" in activesync
    assert "X-Bastion-Session-Cookie $bastion_pass_session" in activesync
    assert "X-Bastion-Session-From-Jar $bastion_session_from_jar" in activesync
    assert "proxy_set_header Cookie          $bastion_auth_cookie;" in activesync


def test_login_alias_bypasses_portal_auth_request():
    """Bare /login must not hit location / auth_request (subdomain rd= bounce loop)."""
    for rel in (
        "docker/nginx/templates/vhost_sso_portal.conf.template",
        "nginx/vhosts/vhost_sso_portal.conf.j2",
    ):
        path = ROOT / rel
        text = path.read_text(encoding="utf-8")
        assert "location = /login" in text, f"{rel} missing location = /login"
        idx = text.index("location = /login")
        block = text[idx : idx + 400]
        assert "auth_request off" in block, f"{rel} /login must disable auth_request"


def test_docker_portal_no_duplicate_security_headers_at_server():
    """F-09: edge owns HSTS/CSP; docker must not re-add overlapping add_header."""
    path = ROOT / "docker/nginx/templates/vhost_sso_portal.conf.template"
    text = path.read_text(encoding="utf-8")
    # Server-level security headers removed (comment documents edge ownership).
    assert "add_header X-Content-Type-Options" not in text.split("location")[0]
    assert "add_header Strict-Transport-Security" not in text
    assert "edge reverse proxy" in text.lower() or "reverse01" in text.lower()


def test_docker_nginx_real_ip_does_not_trust_client_x_real_ip():
    """X-Real-IP to FastAPI must come from real_ip / edge portal header, not $http_x_real_ip."""
    map_text = (ROOT / "docker/nginx/includes/nginx-portal-client-ip.map.conf").read_text(
        encoding="utf-8"
    )
    # Map must not *use* the client-spoofable X-Real-IP header as the value.
    assert "default $http_x_real_ip" not in map_text
    assert "map $http_x_real_ip" not in map_text
    assert "map $remote_addr $portal_remote_is_infra" in map_text
    assert "$http_x_portal_client_ip" in map_text
    assert "$portal_client_real_ip" in map_text
    assert "$remote_addr" in map_text

    nginx_conf = (ROOT / "docker/nginx/nginx.conf").read_text(encoding="utf-8")
    assert "set_real_ip_from 172.24.0.108" in nginx_conf
    assert "set_real_ip_from 10.5.0.0/16" in nginx_conf
    assert "real_ip_header X-Forwarded-For" in nginx_conf
    assert "real_ip_recursive on" in nginx_conf
    assert "forwardedHeaders.trustedIPs" in nginx_conf
    # Must not trust the whole Internet or whole corp LAN as real_ip sources.
    real_ip_from_lines = [
        ln.strip()
        for ln in nginx_conf.splitlines()
        if ln.strip().startswith("set_real_ip_from")
    ]
    assert real_ip_from_lines
    joined = "\n".join(real_ip_from_lines)
    assert "0.0.0.0/0" not in joined
    assert "172.24.0.0/16" not in joined
    assert "172.24.0.108" in joined
    assert "10.5.0.0/16" in joined
    forwarded = (ROOT / "docker/nginx/snippets/proxy_portal_forwarded.conf").read_text(
        encoding="utf-8"
    )
    assert "X-Real-IP $portal_client_real_ip" in forwarded
    # Both headers carry the resolved client (keeps app X-Real / XFF in sync).
    assert "X-Forwarded-For $portal_client_real_ip" in forwarded
    proxy_lines = [
        ln.strip()
        for ln in forwarded.splitlines()
        if ln.strip().startswith("proxy_set_header")
    ]
    proxy_blob = "\n".join(proxy_lines)
    assert "$http_x_real_ip" not in proxy_blob
    assert "$proxy_add_x_forwarded_for" not in proxy_blob


def test_docker_nginx_real_ip_contract_documented():
    """Ops doc + nginx comments must state both edge and Traefik are required."""
    doc = (ROOT / "docs/ops-client-ip-chain.md").read_text(encoding="utf-8")
    assert "Traefik" in doc
    assert "172.24.0.108" in doc
    assert "resolved" in doc
    assert "awx-playbook" in doc
    nginx_conf = (ROOT / "docker/nginx/nginx.conf").read_text(encoding="utf-8")
    assert "Traefik" in nginx_conf
    assert "Neither alone" in nginx_conf or "neither alone" in nginx_conf.lower() or "Both hops" in nginx_conf


def test_breakglass_api_locations_lan_only_before_api_admin():
    """F-06: login/logout exact locations with LAN allow + no auth_request."""
    for rel in (
        "docker/nginx/templates/vhost_sso_portal.conf.template",
        "nginx/vhosts/vhost_sso_portal.conf.j2",
    ):
        path = ROOT / rel
        text = path.read_text(encoding="utf-8")
        for endpoint in (
            "/api/admin/breakglass/login",
            "/api/admin/breakglass/logout",
        ):
            assert f"location = {endpoint}" in text, f"{rel} missing {endpoint}"
            idx = text.index(f"location = {endpoint}")
            block = text[idx : idx + 450]
            assert "auth_request off" in block
            assert "allow 10.0.0.0/8" in block
            assert "deny all" in block
        # Exact recovery locations must appear before the catch-all ^~ /api/admin
        login_idx = text.index("location = /api/admin/breakglass/login")
        admin_idx = text.index("location ^~ /api/admin")
        assert login_idx < admin_idx, f"{rel}: breakglass login must precede ^~ /api/admin"


def test_session_cookie_hop_api_bypasses_portal_auth_request():
    """Hop is public (HMAC cookie); must not hit @portal_oauth2_signin → /auth/login?rd=/apps."""
    for rel in (
        "docker/nginx/templates/vhost_sso_portal.conf.template",
        "nginx/vhosts/vhost_sso_portal.conf.j2",
    ):
        path = ROOT / rel
        text = path.read_text(encoding="utf-8")
        for endpoint in (
            "/api/internal/session-cookie-hop",
            "/api/internal/crush-cookie-hop",
        ):
            assert f"location = {endpoint}" in text, f"{rel} missing {endpoint}"
            idx = text.index(f"location = {endpoint}")
            block = text[idx : idx + 400]
            assert "auth_request off" in block, f"{rel} {endpoint}"
        hop_idx = text.index("location = /api/internal/session-cookie-hop")
        internal_idx = text.index("location ^~ /api/internal/")
        assert hop_idx < internal_idx, f"{rel}: hop must precede ^~ /api/internal/"

