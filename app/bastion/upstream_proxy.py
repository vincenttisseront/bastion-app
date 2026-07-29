"""Normalize upstream_url for nginx ``proxy_pass`` with variables."""

from __future__ import annotations

from urllib.parse import urlparse


def upstream_origin(upstream_url: str) -> str:
    """
    Return ``scheme://host[:port]`` only (no path) for ``$app_upstream``.

    ``proxy_pass $var`` with a path inside ``$var`` replaces the *entire*
    request URI with that path. Values like ``https://ip/web`` therefore turn
    every request into ``GET /web``, which makes apps that 301 ``/web`` →
    ``/web/`` (Grommunio, Teleport) loop forever.

    Subdomain/public proxy is URI-transparent: the browser path is forwarded
    as-is. Do not put ``/web`` (or other app entry paths) in ``upstream_url`` —
    point at the backend origin only. A path in the DB value is ignored here.
    """
    raw = (upstream_url or "").strip()
    parsed = urlparse(raw)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"invalid upstream_url (need scheme + host): {upstream_url!r}")
    return f"{parsed.scheme}://{parsed.netloc}"
