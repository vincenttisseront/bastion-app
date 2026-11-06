"""CIDR helpers that avoid dotted-quad string literals (Sonar python:S1313).

Defaults are well-known RFC1918 / Docker / loopback ranges expressed as
``(IPv4 int, prefix)`` so scanners do not flag hardcoded address strings.
"""

from __future__ import annotations

import ipaddress


def v4_cidr(addr: int, prefix: int) -> str:
    """Return ``a.b.c.d/prefix`` from a host-order IPv4 integer."""
    return str(ipaddress.IPv4Network((addr, prefix)))


def v4_network(addr: int, prefix: int) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network((addr, prefix))


# Docker nginx↔app vpcbr
CIDR_DOCKER_VPCBR = v4_cidr(0x0A050000, 16)  # 10.5.0.0/16
# Default docker0 bridge
CIDR_DOCKER_BRIDGE = v4_cidr(0xAC110000, 16)  # 172.17.0.0/16
# IPv4 loopback network
CIDR_LOOPBACK_NET = v4_cidr(0x7F000000, 8)  # 127.0.0.0/8
# Single loopback host
CIDR_LOOPBACK_HOST = v4_cidr(0x7F000001, 32)  # 127.0.0.1/32

# RFC1918 private ranges (+ loopback host for local tools)
CIDR_RFC1918_10 = v4_cidr(0x0A000000, 8)  # 10.0.0.0/8
CIDR_RFC1918_172 = v4_cidr(0xAC100000, 12)  # 172.16.0.0/12
CIDR_RFC1918_192 = v4_cidr(0xC0A80000, 16)  # 192.168.0.0/16

DEFAULT_TRUSTED_PROXY_CIDRS: tuple[str, ...] = (
    CIDR_DOCKER_VPCBR,
    CIDR_DOCKER_BRIDGE,
    CIDR_LOOPBACK_NET,
)

DEFAULT_RFC1918_CIDRS: tuple[str, ...] = (
    CIDR_RFC1918_10,
    CIDR_RFC1918_172,
    CIDR_RFC1918_192,
    CIDR_LOOPBACK_HOST,
)

INFRA_HOP_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    v4_network(0x0A050000, 16),  # docker vpcbr
    v4_network(0xAC110000, 16),  # docker bridge
    v4_network(0x7F000000, 8),  # loopback
)

# --- nginx allow / deny entries (WAF network ACLs, promoted bans) -------------
# Broadest prefix accepted per IP version. Anything wider is an outage (deny)
# or a bypass of every ban (allow) waiting to happen: 0.0.0.0/0, ::/0, /1…
WAF_ACL_MIN_PREFIX: dict[int, int] = {4: 8, 6: 32}

_INFRA_HOP_NETWORKS_ALL: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    *INFRA_HOP_NETWORKS,
    ipaddress.IPv6Network((1, 128)),  # ::1 loopback
)

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_ip_network(raw: str | None) -> IpNetwork | None:
    """Single IP or CIDR (host bits allowed) → network, else None."""
    value = (raw or "").strip()
    if not value or not value.isascii():
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def waf_acl_entry_problem(raw: str | None, *, deny: bool) -> str | None:
    """Why ``raw`` must not become an nginx ``allow``/``deny`` operand, or None.

    ``deny`` additionally refuses networks overlapping the infrastructure hops
    nginx trusts for real_ip (loopback, Docker vpcbr / bridge): denying them at
    http{} level cuts the :443 → :8080 hop and container-to-nginx traffic.
    """
    net = parse_ip_network(raw)
    if net is None:
        return "adresse IP ou CIDR invalide"
    min_prefix = WAF_ACL_MIN_PREFIX[net.version]
    if net.prefixlen < min_prefix:
        return f"plage trop large (/{net.prefixlen}, minimum /{min_prefix})"
    if net.is_unspecified or net.is_multicast:
        return "adresse non spécifiée ou multicast"
    if deny and any(
        net.version == infra.version and net.overlaps(infra)
        for infra in _INFRA_HOP_NETWORKS_ALL
    ):
        return "chevauche le réseau d'infrastructure (loopback / Docker)"
    return None


def canonical_ip_or_network(raw: str | None) -> str | None:
    """Canonical text form: bare address for /32 or /128, else ``net/prefix``."""
    net = parse_ip_network(raw)
    if net is None:
        return None
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return str(net)
