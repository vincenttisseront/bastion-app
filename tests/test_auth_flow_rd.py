"""safe_post_login_rd — relative + same-parent absolute redirects."""

from __future__ import annotations

from app.auth.flow import safe_post_login_rd


def test_safe_rd_relative_paths():
    assert safe_post_login_rd("/apps") == "/apps"
    assert safe_post_login_rd("/catalogue") == "/catalogue"
    assert safe_post_login_rd("/dashboard") == "/apps"
    assert safe_post_login_rd("//evil.example/") == "/apps"


def test_safe_rd_absolute_same_parent():
    portal = "portal.example.com"
    assert (
        safe_post_login_rd(
            "https://transfer.example.com/WebInterface/new-ui/index.html",
            portal_domain=portal,
        )
        == "https://transfer.example.com/WebInterface/new-ui/index.html"
    )
    assert (
        safe_post_login_rd(
            "https://transfer.example.com/WebInterface/login.html/",
            portal_domain=portal,
        )
        == "https://transfer.example.com/WebInterface/login.html/"
    )


def test_safe_rd_rejects_foreign_absolute():
    assert (
        safe_post_login_rd(
            "https://evil.example/phish",
            portal_domain="portal.example.com",
        )
        == "/apps"
    )
    assert (
        safe_post_login_rd(
            "http://transfer.example.com/",
            portal_domain="portal.example.com",
        )
        == "/apps"
    )
