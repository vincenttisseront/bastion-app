"""Target session cookie Path/Domain — host_only default, wide_domain opt-in."""

from __future__ import annotations

from fastapi.responses import Response

from app.robotic.robotic_session_cookies import (
    COOKIE_SCOPE_HOST_ONLY,
    COOKIE_SCOPE_WIDE_DOMAIN,
    build_crushftp_response_cookies,
    build_response_cookies,
    cookie_path_and_domain,
    inject_target_session_cookies,
    needs_session_cookie_hop,
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


def test_portal_sso_cookie_domain():
    from app.robotic.robotic_session_cookies import portal_sso_cookie_domain

    assert portal_sso_cookie_domain("portal.ar-systems.fr") == "ar-systems.fr"
    assert portal_sso_cookie_domain("https://portal.ar-systems.fr/") == "ar-systems.fr"
    assert portal_sso_cookie_domain("portal.local") is None
    assert portal_sso_cookie_domain("ar-systems.fr") is None


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


def test_cookie_path_host_only_subdomain_default_no_domain():
    path, domain = cookie_path_and_domain(
        "subdomain",
        "myapp",
        "app.ar-systems.fr",
        portal_domain="portal.ar-systems.fr",
    )
    assert path == "/"
    assert domain is None


def test_cookie_path_wide_domain_subdomain_uses_shared_parent():
    path, domain = cookie_path_and_domain(
        "subdomain",
        "myapp",
        "app.ar-systems.fr",
        portal_domain="portal.ar-systems.fr",
        scope=COOKIE_SCOPE_WIDE_DOMAIN,
    )
    assert path == "/"
    assert domain == "ar-systems.fr"


def test_cookie_path_and_domain_legacy_unchanged():
    path, domain = cookie_path_and_domain(
        "legacy",
        "transfer",
        "transfer.ar-systems.fr",
        portal_domain="portal.ar-systems.fr",
        scope=COOKIE_SCOPE_WIDE_DOMAIN,
    )
    assert path == "/proxy/transfer/"
    assert domain is None


def test_needs_session_cookie_hop_host_only_subdomain():
    assert needs_session_cookie_hop(
        "subdomain", "app.ar-systems.fr", scope=COOKIE_SCOPE_HOST_ONLY
    )
    assert not needs_session_cookie_hop(
        "subdomain", "app.ar-systems.fr", scope=COOKIE_SCOPE_WIDE_DOMAIN
    )
    assert not needs_session_cookie_hop("legacy", None, scope=COOKIE_SCOPE_HOST_ONLY)


def test_inject_target_session_cookies_default_has_no_domain():
    """Generic mock app — Set-Cookie must never include Domain by default."""
    response = Response()
    inject_target_session_cookies(
        response,
        {"sessionid": "abc123xyz", "csrftoken": "tok"},
        mode="subdomain",
        slug="demo-app",
        fqdn="demo.ar-systems.fr",
        portal_domain="portal.ar-systems.fr",
    )
    headers = response.headers.getlist("set-cookie")
    assert any("sessionid=abc123xyz" in h for h in headers)
    assert not any("Domain=" in h or "domain=" in h for h in headers)


def test_inject_opt_in_wide_domain():
    response = Response()
    inject_target_session_cookies(
        response,
        {"sessionid": "wide-sess"},
        mode="subdomain",
        slug="demo-app",
        fqdn="demo.ar-systems.fr",
        portal_domain="portal.ar-systems.fr",
        scope=COOKIE_SCOPE_WIDE_DOMAIN,
    )
    headers = response.headers.getlist("set-cookie")
    cookie = next(h for h in headers if h.startswith("sessionid="))
    assert "Domain=ar-systems.fr" in cookie or "domain=ar-systems.fr" in cookie


def test_portal_sso_shared_parent_helper_unchanged():
    """Portal SSO Domain=<parent> helper must keep working (non-regression)."""
    assert (
        shared_parent_domain("portal.ar-systems.fr", "transfer.ar-systems.fr")
        == "ar-systems.fr"
    )
    assert (
        shared_parent_domain("webmail.ar-systems.fr", "portal.ar-systems.fr")
        == "ar-systems.fr"
    )


def test_build_crushftp_host_only_by_default():
    response = Response()
    build_crushftp_response_cookies(
        response,
        {"CrushAuth": "ABCDEFGH1234", "currentAuth": "1234"},
        mode="subdomain",
        slug="transfer",
        fqdn="transfer.ar-systems.fr",
        portal_domain="portal.ar-systems.fr",
    )
    headers = response.headers.getlist("set-cookie")
    assert any("CrushAuth=" in h for h in headers)
    assert not any("Domain=" in h or "domain=" in h for h in headers)
    crush = next(h for h in headers if h.startswith("CrushAuth="))
    current = next(h for h in headers if h.startswith("currentAuth="))
    assert "HttpOnly" in crush or "httponly" in crush.lower()
    assert "HttpOnly" not in current and "httponly" not in current.lower()


def test_build_grommunio_cookies_host_only_by_default():
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
        assert "Domain=" not in cookie and "domain=" not in cookie


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
