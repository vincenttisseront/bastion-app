"""Robotic session cookie Path/Domain helpers."""

from __future__ import annotations

from fastapi.responses import Response

from app.robotic.robotic_session_cookies import (
    build_crushftp_response_cookies,
    build_response_cookies,
    cookie_path_and_domain,
    normalize_hostname,
    shared_parent_domain,
)


def test_shared_parent_transfer_and_portal():
    assert (
        shared_parent_domain("transfer.ar-systems.fr", "portal.ar-systems.fr")
        == "ar-systems.fr"
    )


def test_shared_parent_webmail_and_portal():
    assert (
        shared_parent_domain("webmail.ar-systems.fr", "portal.ar-systems.fr")
        == "ar-systems.fr"
    )


def test_shared_parent_when_portal_domain_is_apex():
    assert shared_parent_domain("transfer.ar-systems.fr", "ar-systems.fr") == "ar-systems.fr"


def test_shared_parent_none_for_unrelated_domains():
    assert shared_parent_domain("app.exemple-externe.com", "portal.ar-systems.fr") is None
    assert shared_parent_domain("exemple.com", "portal.ar-systems.fr") is None


def test_shared_parent_rejects_tld_only():
    assert shared_parent_domain("foo.com", "bar.com") is None


def test_shared_parent_normalizes_url_and_port():
    assert (
        shared_parent_domain("https://webmail.ar-systems.fr/", "portal.ar-systems.fr")
        == "ar-systems.fr"
    )
    assert (
        shared_parent_domain("webmail.ar-systems.fr:443", "https://portal.ar-systems.fr")
        == "ar-systems.fr"
    )


def test_normalize_hostname():
    assert normalize_hostname("webmail.ar-systems.fr") == "webmail.ar-systems.fr"
    assert normalize_hostname("https://webmail.ar-systems.fr/") == "webmail.ar-systems.fr"
    assert normalize_hostname("webmail.ar-systems.fr:8443") == "webmail.ar-systems.fr"
    assert normalize_hostname("  PORTAL.AR-SYSTEMS.FR. ") == "portal.ar-systems.fr"


def test_cookie_path_and_domain_subdomain_shared_parent():
    path, domain = cookie_path_and_domain(
        "subdomain",
        "transfer",
        "transfer.ar-systems.fr",
        portal_domain="portal.ar-systems.fr",
    )
    assert path == "/"
    assert domain == "ar-systems.fr"


def test_cookie_path_and_domain_webmail_shared_parent():
    path, domain = cookie_path_and_domain(
        "subdomain",
        "grommunio",
        "webmail.ar-systems.fr",
        portal_domain="portal.ar-systems.fr",
    )
    assert path == "/"
    assert domain == "ar-systems.fr"


def test_cookie_path_and_domain_subdomain_no_shared_parent():
    path, domain = cookie_path_and_domain(
        "subdomain",
        "ext",
        "app.exemple-externe.com",
        portal_domain="portal.ar-systems.fr",
    )
    assert path == "/"
    assert domain is None


def test_cookie_path_and_domain_legacy_unchanged():
    path, domain = cookie_path_and_domain(
        "legacy",
        "transfer",
        "transfer.ar-systems.fr",
        portal_domain="portal.ar-systems.fr",
    )
    assert path == "/proxy/transfer/"
    assert domain is None


def test_build_crushftp_sets_shared_domain(caplog):
    response = Response()
    build_crushftp_response_cookies(
        response,
        {"CrushAuth": "ABCDEFGH1234", "currentAuth": "1234"},
        mode="subdomain",
        slug="transfer",
        fqdn="transfer.ar-systems.fr",
        portal_domain="portal.ar-systems.fr",
    )
    # Starlette stores cookies; inspect raw Set-Cookie headers
    headers = response.headers.getlist("set-cookie")
    assert any("CrushAuth=" in h for h in headers)
    assert any("Domain=ar-systems.fr" in h or "domain=ar-systems.fr" in h for h in headers)
    assert not any("Domain=transfer.ar-systems.fr" in h for h in headers)
    crush = next(h for h in headers if h.startswith("CrushAuth="))
    current = next(h for h in headers if h.startswith("currentAuth="))
    assert "HttpOnly" in crush or "httponly" in crush.lower()
    assert "HttpOnly" not in current and "httponly" not in current.lower()


def test_build_grommunio_cookies_use_shared_parent_domain():
    response = Response()
    build_response_cookies(
        response,
        {
            "__Secure-GROMMUNIO_WEB": "sess-token-abc",
            "domainname": "ar-systems.fr",
            "webapp_title": "Webmail",
            "grommunioAuthJwt": "eyJ.test.jwt",
        },
        mode="subdomain",
        slug="grommunio",
        fqdn="webmail.ar-systems.fr",
        portal_domain="portal.ar-systems.fr",
    )
    headers = response.headers.getlist("set-cookie")
    assert any("__Secure-GROMMUNIO_WEB=" in h for h in headers)
    for name in ("__Secure-GROMMUNIO_WEB", "domainname", "webapp_title", "grommunioAuthJwt"):
        cookie = next(h for h in headers if h.startswith(f"{name}="))
        assert "Domain=ar-systems.fr" in cookie or "domain=ar-systems.fr" in cookie
        assert "Domain=webmail.ar-systems.fr" not in cookie
        assert "Domain=portal.ar-systems.fr" not in cookie


def test_build_response_cookies_legacy_no_domain():
    response = Response()
    build_response_cookies(
        response,
        {"sessionid": "abc"},
        mode="legacy",
        slug="wiki",
        fqdn=None,
        portal_domain="portal.ar-systems.fr",
    )
    headers = response.headers.getlist("set-cookie")
    assert any("sessionid=abc" in h for h in headers)
    assert any("Path=/proxy/wiki/" in h or "path=/proxy/wiki/" in h for h in headers)
    assert not any("Domain=" in h or "domain=" in h for h in headers)
