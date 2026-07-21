"""Extract the original client IP from proxy headers."""

from __future__ import annotations

import ipaddress

from fastapi import Request

# Intermediate hops on the bastion path (reverse01 → Traefik → nginx → app).
# Prefer a non-infra address from X-Forwarded-For / X-Real-IP when present.
_INFRA_NETWORKS = (
    ipaddress.ip_network("10.5.0.0/16"),  # docker vpcbr
    ipaddress.ip_network("172.24.0.0/16"),  # docker01 Traefik / LAN bridge
    ipaddress.ip_network("172.17.0.0/16"),  # default docker bridge
    ipaddress.ip_network("127.0.0.0/8"),
)


def _first_ip(value: str | None) -> str | None:
    if not value:
        return None
    part = value.split(",")[0].strip()
    return part or None


def is_infra_hop(ip: str | None) -> bool:
    """True for docker/proxy LAN addresses that are not useful as client IP."""
    if not ip or not str(ip).strip():
        return True
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return True
    return any(addr in net for net in _INFRA_NETWORKS)


def prefer_client_ip(existing: str | None, new: str | None) -> str | None:
    """
    Keep the first real client IP; upgrade only when the stored value was an
    infra hop and the new one looks like a real client.
    """
    new = (new or "").strip() or None
    existing = (existing or "").strip() or None
    if not new:
        return existing
    if not existing:
        return new
    if is_infra_hop(existing) and not is_infra_hop(new):
        return new
    return existing


def _candidates(request: Request) -> list[str]:
    out: list[str] = []
    xff = request.headers.get("X-Forwarded-For") or ""
    for part in xff.split(","):
        ip = part.strip()
        if ip:
            out.append(ip)
    real = (request.headers.get("X-Real-IP") or "").strip()
    if real:
        out.append(real)
    if request.client and request.client.host:
        out.append(request.client.host)
    # de-dupe preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for ip in out:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique


def client_ip_from_request(request: Request) -> str:
    """
    Prefer the leftmost non-infra hop in X-Forwarded-For, then X-Real-IP,
    then the TCP peer. Skips docker/Traefik LAN addresses when a real client
    IP is present further in the chain (or as X-Real-IP from the edge).
    """
    candidates = _candidates(request)
    for ip in candidates:
        if not is_infra_hop(ip):
            return ip
    return candidates[0] if candidates else ""
