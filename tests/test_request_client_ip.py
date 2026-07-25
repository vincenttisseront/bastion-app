"""Unit tests for trusted-proxy client IP extraction."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.request_client_ip import (
    client_ip_from_request,
    is_infra_hop,
    is_trusted_proxy_peer,
    prefer_client_ip,
)


def _req(*, headers: dict | None = None, host: str | None = "127.0.0.1"):
    request = MagicMock()
    request.headers = headers or {}
    if host is None:
        request.client = None
    else:
        request.client = MagicMock(host=host)
    return request


def test_prefers_leftmost_xff_over_infra_x_real_ip():
    ip = client_ip_from_request(
        _req(
            headers={
                "X-Forwarded-For": "192.168.2.167, 10.5.0.3",
                "X-Real-IP": "10.5.0.3",
            },
            host="10.5.0.2",
        )
    )
    assert ip == "192.168.2.167"


def test_skips_infra_xff_hops_for_real_client():
    """Traefik/nginx LAN first in chain must not win over a real client as X-Real-IP."""
    ip = client_ip_from_request(
        _req(
            headers={
                "X-Forwarded-For": "172.24.0.108, 10.5.0.12",
                "X-Real-IP": "192.168.2.167",
            },
            host="10.5.0.1",
        )
    )
    assert ip == "192.168.2.167"


def test_client_ip_probe_exposes_sources():
    from app.request_client_ip import client_ip_probe

    probe = client_ip_probe(
        _req(
            headers={
                "X-Real-IP": "203.0.113.1",
                "X-Forwarded-For": "203.0.113.1, 172.24.0.108",
            },
            host="10.5.0.9",
        )
    )
    assert probe["x_real_ip"] == "203.0.113.1"
    assert probe["x_forwarded_for"] == "203.0.113.1, 172.24.0.108"
    assert probe["request_client_host"] == "10.5.0.9"
    assert probe["peer_is_trusted_proxy"] is True
    assert probe["resolved"] == "203.0.113.1"
    assert probe["resolved_is_infra"] is False


def test_falls_back_to_x_real_ip_from_trusted_peer():
    assert (
        client_ip_from_request(_req(headers={"X-Real-IP": "10.1.2.3"}, host="127.0.0.1"))
        == "10.1.2.3"
    )


def test_untrusted_peer_ignores_headers_uses_socket():
    """Direct FastAPI hit: spoofed RFC1918 headers must not win."""
    ip = client_ip_from_request(
        _req(
            headers={
                "X-Real-IP": "10.0.0.50",
                "X-Forwarded-For": "10.0.0.50",
                "CF-Connecting-IP": "192.168.1.1",
            },
            host="203.0.113.99",
        )
    )
    assert ip == "203.0.113.99"


def test_untrusted_peer_no_headers_uses_socket():
    assert client_ip_from_request(_req(headers={}, host="10.0.0.9")) == "10.0.0.9"


def test_x_real_ip_preferred_over_tcp_peer_when_trusted():
    """Session capture must not use request.client.host alone when nginx set X-Real-IP."""
    ip = client_ip_from_request(
        _req(headers={"X-Real-IP": "203.0.113.50"}, host="10.5.0.2")
    )
    assert ip == "203.0.113.50"
    assert ip != "10.5.0.2"


def test_reverse01_never_used_as_client_ip():
    """If only the DMZ reverse IP is visible, resolve empty (fail closed for LAN)."""
    ip = client_ip_from_request(
        _req(
            headers={
                "X-Real-IP": "172.24.0.108",
                "X-Forwarded-For": "172.24.0.108",
            },
            host="10.5.0.2",
        )
    )
    assert ip == ""
    assert ip != "172.24.0.108"
    assert is_infra_hop("172.24.0.108")


def test_ignores_cdn_spoof_headers_even_from_trusted_peer():
    ip = client_ip_from_request(
        _req(
            headers={
                "CF-Connecting-IP": "10.0.0.1",
                "True-Client-IP": "10.0.0.2",
                "X-Client-IP": "10.0.0.3",
                "X-Real-IP": "203.0.113.40",
            },
            host="10.5.0.2",
        )
    )
    assert ip == "203.0.113.40"


def test_prefer_client_ip_upgrades_infra():
    assert prefer_client_ip("172.24.0.108", "192.168.2.10") == "192.168.2.10"
    assert prefer_client_ip("192.168.2.10", "172.24.0.108") == "192.168.2.10"
    assert is_infra_hop("172.24.0.108")
    assert not is_infra_hop("192.168.2.10")
    assert is_trusted_proxy_peer("10.5.0.1")
    assert not is_trusted_proxy_peer("203.0.113.1")
