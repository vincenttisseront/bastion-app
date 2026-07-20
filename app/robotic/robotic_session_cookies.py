"""Set robotic session cookies on a FastAPI Response."""

from __future__ import annotations

from typing import Literal

from fastapi import Response

# CrushFTP legacy cookie names (used when cookie_keys not specified).
CRUSHFTP_COOKIE_KEYS = ("CrushAuth", "currentAuth")


def cookie_path_and_domain(
    mode: Literal["subdomain", "legacy"],
    slug: str,
    fqdn: str | None,
) -> tuple[str, str | None]:
    """Compute Path and Domain for robotic session cookies."""
    if mode == "subdomain":
        return "/", (fqdn or "").strip() or None
    return f"/proxy/{slug}/", None


def build_response_cookies(
    response: Response,
    cookies: dict[str, str],
    mode: Literal["subdomain", "legacy"],
    slug: str,
    fqdn: str | None,
    *,
    cookie_keys: tuple[str, ...] | None = None,
) -> None:
    """
    Set session cookies on the FastAPI response.

    - mode "subdomain" : Path=/, Domain={fqdn}
    - mode "legacy"    : Path=/proxy/{slug}/, no Domain
    Always httponly=True, secure=True, samesite="lax".
    """
    path, domain = cookie_path_and_domain(mode, slug, fqdn)
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
) -> None:
    """Backward-compatible CrushFTP cookie setter."""
    build_response_cookies(
        response,
        cookies,
        mode,
        slug,
        fqdn,
        cookie_keys=CRUSHFTP_COOKIE_KEYS,
    )
