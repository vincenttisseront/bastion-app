"""Set robotic session cookies on a FastAPI Response."""

from __future__ import annotations

import logging
from typing import Literal

from fastapi import Response

logger = logging.getLogger(__name__)

# CrushFTP legacy cookie names (used when cookie_keys not specified).
CRUSHFTP_COOKIE_KEYS = ("CrushAuth", "currentAuth")


def shared_parent_domain(fqdn: str, portal_domain: str) -> str | None:
    """
    Return the shortest common parent domain of two hostnames, or None.

    Browsers only accept Set-Cookie Domain values that are the response host
    or a parent domain. Setting Domain=transfer.example.fr from
    portal.example.fr is rejected; Domain=example.fr works for both.
    Requires at least two labels (e.g. example.fr), never a bare TLD.
    """
    fqdn_labels = fqdn.strip().strip(".").lower().split(".")
    portal_labels = portal_domain.strip().strip(".").lower().split(".")
    if not fqdn_labels or not portal_labels or "" in fqdn_labels or "" in portal_labels:
        return None
    common: list[str] = []
    for a, b in zip(reversed(fqdn_labels), reversed(portal_labels)):
        if a != b:
            break
        common.append(a)
    if len(common) < 2:
        return None
    return ".".join(reversed(common))


def cookie_path_and_domain(
    mode: Literal["subdomain", "legacy"],
    slug: str,
    fqdn: str | None,
    portal_domain: str = "",
) -> tuple[str, str | None]:
    """Compute Path and Domain for robotic session cookies."""
    if mode == "subdomain":
        fqdn_clean = (fqdn or "").strip()
        if not fqdn_clean:
            return "/", None
        shared = shared_parent_domain(fqdn_clean, portal_domain or "")
        if shared is None:
            logger.warning(
                "No shared parent domain between app FQDN %r and portal %r — "
                "cross-subdomain session cookies cannot be set by the browser",
                fqdn_clean,
                portal_domain,
            )
            return "/", None
        return "/", shared
    return f"/proxy/{slug}/", None


def build_response_cookies(
    response: Response,
    cookies: dict[str, str],
    mode: Literal["subdomain", "legacy"],
    slug: str,
    fqdn: str | None,
    *,
    portal_domain: str = "",
    cookie_keys: tuple[str, ...] | None = None,
) -> None:
    """
    Set session cookies on the FastAPI response.

    - mode "subdomain" : Path=/, Domain={shared parent of fqdn and portal}
    - mode "legacy"    : Path=/proxy/{slug}/, no Domain
    Always httponly=True, secure=True, samesite="lax".
    """
    path, domain = cookie_path_and_domain(mode, slug, fqdn, portal_domain=portal_domain)
    keys = cookie_keys if cookie_keys is not None else tuple(cookies.keys())
    if not keys:
        keys = tuple(cookies.keys())

    for key in keys:
        value = cookies.get(key)
        if not value:
            continue
        kwargs: dict = {
            "key": key,
            "value": value,
            "path": path,
            "httponly": True,
            "secure": True,
            "samesite": "lax",
        }
        if domain:
            kwargs["domain"] = domain
        response.set_cookie(**kwargs)


def build_crushftp_response_cookies(
    response: Response,
    cookies: dict[str, str],
    mode: Literal["subdomain", "legacy"],
    slug: str,
    fqdn: str | None,
    *,
    portal_domain: str = "",
) -> None:
    """Backward-compatible CrushFTP cookie setter."""
    build_response_cookies(
        response,
        cookies,
        mode,
        slug,
        fqdn,
        portal_domain=portal_domain,
        cookie_keys=CRUSHFTP_COOKIE_KEYS,
    )
