"""Extract the original client IP from proxy headers."""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Any

from fastapi import Request

logger = logging.getLogger(__name__)

# Intermediate hops on the bastion path (reverse01 → Traefik → nginx → app).
_INFRA_NETWORKS = (
    ipaddress.ip_network("10.5.0.0/16"),  # docker vpcbr
    ipaddress.ip_network("172.24.0.0/16"),  # docker01 Traefik / LAN bridge
    ipaddress.ip_network("172.17.0.0/16"),  # default docker bridge
    ipaddress.ip_network("127.0.0.0/8"),
)

# Set SESSIONS_IP_PROBE=1 to log the three sources on every resolve (temporary diag).
_IP_PROBE = os.environ.get("SESSIONS_IP_PROBE", "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)


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


def client_ip_probe(request: Request) -> dict[str, Any]:
    """
    Snapshot of the three IP sources for diagnostics (prompt v2).
    Does not mutate state — safe to expose to portal admins.
    """
    x_real = (request.headers.get("X-Real-IP") or "").strip() or None
    x_fwd = (request.headers.get("X-Forwarded-For") or "").strip() or None
    peer = request.client.host if request.client else None
    resolved = client_ip_from_request(request)
    return {
        "x_real_ip": x_real,
        "x_forwarded_for": x_fwd,
        "request_client_host": peer,
        "resolved": resolved or None,
        "resolved_is_infra": is_infra_hop(resolved),
    }


def _candidates(request: Request) -> list[str]:
    out: list[str] = []
    # Edge / CDN headers first when present
    for header in ("CF-Connecting-IP", "True-Client-IP", "X-Client-IP"):
        val = (request.headers.get(header) or "").strip()
        if val:
            out.append(val)
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
    seen: set[str] = set()
    unique: list[str] = []
    for ip in out:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique


def client_ip_from_request(request: Request) -> str:
    """
    Prefer the leftmost non-infra hop in X-Forwarded-For / edge headers,
    then X-Real-IP, then the TCP peer.
    """
    candidates = _candidates(request)
    resolved = ""
    for ip in candidates:
        if not is_infra_hop(ip):
            resolved = ip
            break
    if not resolved:
        resolved = candidates[0] if candidates else ""

    if _IP_PROBE:
        probe = {
            "x_real_ip": (request.headers.get("X-Real-IP") or "").strip() or None,
            "x_forwarded_for": (request.headers.get("X-Forwarded-For") or "").strip() or None,
            "request_client_host": request.client.host if request.client else None,
            "resolved": resolved or None,
        }
        logger.info("sessions_ip_probe %s", probe)

    return resolved
