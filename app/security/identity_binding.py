"""Identity binding signals: fingerprint + IP subnet (no family policy)."""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Literal

from fastapi import Request

from app.request_client_ip import client_ip_from_request

DriftLevel = Literal["none", "weak", "strong"]

# Cookie name hints for oauth2-proxy (default ``_oauth2_proxy`` and variants).
_OAUTH2_COOKIE_HINTS = ("oauth2_proxy", "_oauth2")


def compute_fingerprint(
    user_agent: str, accept_language: str, accept_encoding: str
) -> str:
    """SHA-256 of UA + Accept-Language + Accept-Encoding, truncated to 32 hex chars."""
    raw = f"{user_agent}|{accept_language}|{accept_encoding}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def compute_ip_subnet(ip: str) -> str:
    """Return IPv4 /24 or IPv6 /64 network string; empty if IP invalid."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
        prefix = 24 if addr.version == 4 else 64
        network = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        return str(network)
    except ValueError:
        return ""


def classify_drift(same_subnet: bool, same_fingerprint: bool) -> DriftLevel:
    """
    Classify identity drift vs login anchor.

    - none: same subnet and fingerprint
    - weak: fingerprint changed, subnet unchanged (e.g. browser update)
    - strong: subnet changed (with or without fingerprint change) — classic replay
    """
    if same_subnet and same_fingerprint:
        return "none"
    if same_subnet and not same_fingerprint:
        return "weak"
    return "strong"


def fingerprint_from_request(request: Request) -> str:
    return compute_fingerprint(
        (request.headers.get("User-Agent") or "").strip(),
        (request.headers.get("Accept-Language") or "").strip(),
        (request.headers.get("Accept-Encoding") or "").strip(),
    )


def subnet_from_request(request: Request) -> str:
    return compute_ip_subnet(client_ip_from_request(request))


def hash_cookie_value(cookie_value: str) -> str:
    """SHA-256 hex of a cookie value (never store plaintext)."""
    return hashlib.sha256((cookie_value or "").encode("utf-8")).hexdigest()


def is_oauth2_proxy_cookie_name(name: str) -> bool:
    n = (name or "").lower()
    return any(hint in n for hint in _OAUTH2_COOKIE_HINTS)


def oauth2_proxy_cookie_hash(request: Request) -> str | None:
    """
    Stable hash of oauth2-proxy session cookie(s) on the request.

    Uses sorted ``name=value`` pairs so multi-cookie setups stay deterministic.
    Returns None when no oauth2-proxy cookie is present.
    """
    parts: list[str] = []
    for name in sorted(request.cookies.keys()):
        if not is_oauth2_proxy_cookie_name(name):
            continue
        value = (request.cookies.get(name) or "").strip()
        if value:
            parts.append(f"{name}={value}")
    if not parts:
        return None
    return hash_cookie_value("|".join(parts))
