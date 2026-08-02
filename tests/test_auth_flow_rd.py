"""safe_post_login_rd — relative + same-parent absolute redirects."""

from __future__ import annotations

from app.auth_flow import safe_post_login_rd


def test_safe_rd_relative_paths():
    assert safe_post_login_rd("/apps") == "/apps"
    assert safe_post_login_rd("/catalogue") == "/catalogue"
    assert safe_post_login_rd("/dashboard") == "/apps"
    assert safe_post_login_rd("//evil.example/") == "/apps"


def test_safe_rd_absolute_same_parent():
    portal = "portal.ar-systems.fr"
    assert (
        safe_post_login_rd(
            "https://transfer.ar-systems.fr/WebInterface/new-ui/index.html",
            portal_domain=portal,
        )
        == "https://transfer.ar-systems.fr/WebInterface/new-ui/index.html"
    )
    assert (
        safe_post_login_rd(
            "https://transfer.ar-systems.fr/WebInterface/login.html/",
            portal_domain=portal,
        )
        == "https://transfer.ar-systems.fr/WebInterface/login.html/"
    )


def test_safe_rd_rejects_foreign_absolute():
    assert (
        safe_post_login_rd(
            "https://evil.example/phish",
            portal_domain="portal.ar-systems.fr",
        )
        == "/apps"
    )
    assert (
        safe_post_login_rd(
            "http://transfer.ar-systems.fr/",
            portal_domain="portal.ar-systems.fr",
        )
        == "/apps"
    )
