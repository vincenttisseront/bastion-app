"""Set CrushFTP robotic session cookies on a FastAPI Response."""

from __future__ import annotations

from typing import Literal

from fastapi import Response

COOKIE_KEYS = ("CrushAuth", "currentAuth")


def build_response_cookies(
    response: Response,
    cookies: dict[str, str],
    mode: Literal["subdomain", "legacy"],
    slug: str,
    fqdn: str | None,
) -> None:
    """
    Pose CrushAuth et currentAuth sur la Response FastAPI.

    - mode "subdomain" : Path=/, Domain={fqdn}
    - mode "legacy"    : Path=/proxy/{slug}/, pas de Domain
    Toujours httponly=True, secure=True, samesite="lax".
    """
    if mode == "subdomain":
        path = "/"
        domain = (fqdn or "").strip() or None
    else:
        path = f"/proxy/{slug}/"
        domain = None

    for key in COOKIE_KEYS:
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
