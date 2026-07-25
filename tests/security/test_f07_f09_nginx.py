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
