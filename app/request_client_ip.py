"""Trusted-proxy client IP resolution (F-01 / F-04).

Fail-safe rule: forwarded headers (X-Real-IP, X-Forwarded-For) are honoured
ONLY when the TCP peer is a configured trusted proxy (nginx-bastion on the
docker network). Otherwise the socket address is used and headers are ignored.

Edge/CDN headers (CF-Connecting-IP, True-Client-IP, X-Client-IP) are never
trusted on this path — there is no Cloudflare (or similar) in front of the
bastion; accepting them would allow trivial spoofing.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from functools import lru_cache
from typing import Any

from fastapi import Request

logger = logging.getLogger(__name__)

# Intermediate hops that are never the end-user client.
# Do NOT mark the whole 172.24.0.0/16 as infra: that is the corp/DMZ LAN where
# workstations live (same range as reverse01). Only the reverse host itself.
_INFRA_NETWORKS = (
    ipaddress.ip_network("10.5.0.0/16"),  # docker vpcbr (Traefik ↔ nginx ↔ app)
    ipaddress.ip_network("172.24.0.108/32"),  # vmdmz-reverse01 (nginx DMZ)
    ipaddress.ip_network("172.17.0.0/16"),  # default docker bridge
    ipaddress.ip_network("127.0.0.0/8"),
)

# TCP peers from which FastAPI may honour X-Real-IP / X-Forwarded-For.
# Default = nginx-bastion → app on docker (+ loopback for TestClient / local).
_DEFAULT_TRUSTED_PROXY_CIDRS = (
    "10.5.0.0/16",
    "172.17.0.0/16",
    "127.0.0.0/8",
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


def _parse_cidrs(raw: list[str] | tuple[str, ...] | None) -> tuple[Any, ...]:
    out: list[Any] = []
    for item in raw or ():
        text = str(item).strip()
        if not text:
            continue
        try:
            out.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid trusted-proxy CIDR: %s", text)
    return tuple(out)


@lru_cache(maxsize=1)
def _trusted_proxy_networks_cached(cidrs_key: str) -> tuple[Any, ...]:
    parts = [p for p in cidrs_key.split("|") if p]
    return _parse_cidrs(parts)


def trusted_proxy_cidrs() -> list[str]:
    """Configured trusted-proxy CIDRs (settings, else defaults)."""
    try:
        from app.sso_settings import get_settings

        cidrs = list(get_settings().trusted_proxy_cidrs or [])
        if cidrs:
            return cidrs
    except Exception:
        pass
    return list(_DEFAULT_TRUSTED_PROXY_CIDRS)


def clear_trusted_proxy_cache() -> None:
    """Tests: drop LRU after monkeypatching TRUSTED_PROXY_CIDRS / settings."""
    _trusted_proxy_networks_cached.cache_clear()


def is_trusted_proxy_peer(peer: str | None) -> bool:
    """True when the TCP peer may set X-Real-IP / X-Forwarded-For."""
    if not peer or not str(peer).strip():
        return False
    peer = str(peer).strip()
    # Starlette/FastAPI TestClient sets client host to the literal "testclient".
    if peer == "testclient":
        return _testclient_peer_trusted()
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    key = "|".join(trusted_proxy_cidrs())
    return any(addr in net for net in _trusted_proxy_networks_cached(key))


def _testclient_peer_trusted() -> bool:
    """Allow header trust only under PORTAL_ENVIRONMENT=test (pytest)."""
    try:
        from app.sso_settings import get_settings

        return get_settings().is_test
    except Exception:
        return os.environ.get("PORTAL_ENVIRONMENT", "").strip().lower() in (
            "test",
            "testing",
            "pytest",
        )


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _xff_client_candidates(xff: str) -> list[str]:
    """Left-to-right XFF entries that look like real (non-infra) clients."""
    out: list[str] = []
    for part in xff.split(","):
        ip = part.strip()
        if ip and _valid_ip(ip) and not is_infra_hop(ip):
            out.append(ip)
    return out


def client_ip_probe(request: Request) -> dict[str, Any]:
    """
    Snapshot of IP sources for diagnostics.
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
        "peer_is_trusted_proxy": is_trusted_proxy_peer(peer),
        "resolved": resolved or None,
        "resolved_is_infra": is_infra_hop(resolved),
    }


def client_ip_from_request(request: Request) -> str:
    """
    Resolve the end-user client IP for access control (break-glass LAN, RFC1918).

    - Untrusted TCP peer → socket address only (headers ignored).
    - Trusted proxy → X-Real-IP if it is a non-infra client; else leftmost
      non-infra hop in X-Forwarded-For; else empty string (fail closed: never
      treat reverse01 ``172.24.0.108`` / Traefik as the user).
    - CF-Connecting-IP / True-Client-IP / X-Client-IP are never read.
    """
    peer = (request.client.host if request.client else "") or ""

    if not is_trusted_proxy_peer(peer):
        resolved = peer
        if _IP_PROBE:
            logger.info(
                "sessions_ip_probe untrusted_peer peer=%s resolved=%s",
                peer,
                resolved,
            )
        return resolved

    x_real = (request.headers.get("X-Real-IP") or "").strip()
    if x_real and _valid_ip(x_real) and not is_infra_hop(x_real):
        resolved = x_real
    else:
        xff = request.headers.get("X-Forwarded-For") or ""
        candidates = _xff_client_candidates(xff)
        resolved = candidates[0] if candidates else ""

    if _IP_PROBE:
        logger.info(
            "sessions_ip_probe trusted_peer peer=%s x_real=%s xff=%s resolved=%s",
            peer,
            x_real or None,
            (request.headers.get("X-Forwarded-For") or "").strip() or None,
            resolved or None,
        )

    return resolved
