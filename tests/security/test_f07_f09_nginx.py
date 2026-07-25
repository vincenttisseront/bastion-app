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


def test_docker_portal_vhost_internal_handlers():
    path = ROOT / "docker/nginx/templates/vhost_sso_portal.conf.template"
    text = path.read_text(encoding="utf-8")
    _assert_internal_locations(text, str(path))
    # auth_request still uses dedicated internal check (not broken by return 404 stubs)
    assert "location = /portal_auth_check" in text
    assert "proxy_pass http://$bastion_app_upstream/internal/oauth2-auth" in text


def test_j2_portal_vhost_internal_handlers():
    path = ROOT / "nginx/vhosts/vhost_sso_portal.conf.j2"
    text = path.read_text(encoding="utf-8")
    _assert_internal_locations(text, str(path))


def test_subdomain_auth_snippet_still_internal():
    path = ROOT / "nginx/snippets/subdomain_auth_common.conf.j2"
    text = path.read_text(encoding="utf-8")
    assert "location = /internal/subdomain-auth" in text
    assert "internal;" in text


def test_docker_portal_no_duplicate_security_headers_at_server():
    """F-09: edge owns HSTS/CSP; docker must not re-add overlapping add_header."""
    path = ROOT / "docker/nginx/templates/vhost_sso_portal.conf.template"
    text = path.read_text(encoding="utf-8")
    # Server-level security headers removed (comment documents edge ownership).
    assert "add_header X-Content-Type-Options" not in text.split("location")[0]
    assert "add_header Strict-Transport-Security" not in text
    assert "edge reverse proxy" in text.lower() or "reverse01" in text.lower()


def test_docker_nginx_real_ip_does_not_trust_client_x_real_ip():
    """X-Real-IP to FastAPI must come from $remote_addr after real_ip, not $http_x_real_ip."""
    map_text = (ROOT / "docker/nginx/includes/nginx-portal-client-ip.map.conf").read_text(
        encoding="utf-8"
    )
    # Map must not *use* the client header as the value (comments may mention it).
    assert "default $http_x_real_ip" not in map_text
    assert "map $http_x_real_ip" not in map_text
    assert "map $remote_addr $portal_client_real_ip" in map_text
    assert "default $remote_addr" in map_text

    nginx_conf = (ROOT / "docker/nginx/nginx.conf").read_text(encoding="utf-8")
    assert "set_real_ip_from 172.24.0.108" in nginx_conf
    assert "real_ip_header X-Forwarded-For" in nginx_conf
    assert "awx-playbook" in nginx_conf or "reverse01" in nginx_conf

    forwarded = (ROOT / "docker/nginx/snippets/proxy_portal_forwarded.conf").read_text(
        encoding="utf-8"
    )
    assert "X-Real-IP $portal_client_real_ip" in forwarded
    # Do not append client-controlled XFF; pass the resolved remote_addr only.
    assert "X-Forwarded-For $remote_addr" in forwarded


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

