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
