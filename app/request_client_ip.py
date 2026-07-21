"""Extract the original client IP from proxy headers."""

from __future__ import annotations

from fastapi import Request


def _first_ip(value: str | None) -> str | None:
    if not value:
        return None
    # X-Forwarded-For: client, proxy1, proxy2 — leftmost is the original client.
    part = value.split(",")[0].strip()
    return part or None


def client_ip_from_request(request: Request) -> str:
    """
    Prefer the leftmost X-Forwarded-For hop (real browser/client), then X-Real-IP,
    then the TCP peer. Avoids recording docker/proxy LAN addresses as source_ip
    when nginx/oauth2-proxy set X-Real-IP to the previous hop only.
    """
    forwarded = _first_ip(request.headers.get("X-Forwarded-For"))
    if forwarded:
        return forwarded
    real = (request.headers.get("X-Real-IP") or "").strip()
    if real:
        return real
    if request.client and request.client.host:
        return request.client.host
    return ""
