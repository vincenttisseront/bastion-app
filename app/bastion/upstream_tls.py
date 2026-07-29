"""TLS verify flag for App upstream (robotic httpx + nginx proxy_ssl_verify)."""

from __future__ import annotations

from typing import Any


def resolve_upstream_tls_verify(app: Any | None, *, default: bool = False) -> bool:
    """
    Whether bastion should verify the upstream TLS certificate.

    Default ``False`` matches common LAN/IP/self-signed backends (same as
    historical nginx ``proxy_ssl_verify off``). Admins opt in via the app UI.
    """
    if app is None:
        return default
    return bool(getattr(app, "upstream_tls_verify", default))


def nginx_proxy_ssl_verify_directive(verify: bool) -> str:
    return "        proxy_ssl_verify on;" if verify else "        proxy_ssl_verify off;"
