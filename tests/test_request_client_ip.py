"""Unit tests for client IP extraction from proxy headers."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.request_client_ip import (
    client_ip_from_request,
    is_infra_hop,
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


def test_prefers_leftmost_xff_over_x_real_ip():
    ip = client_ip_from_request(
        _req(
            headers={
                "X-Forwarded-For": "192.168.2.167, 10.5.0.3",
                "X-Real-IP": "10.5.0.3",
            },
            host="172.24.0.1",
        )
    )
    assert ip == "192.168.2.167"


def test_skips_infra_xff_hops_for_real_client():
    """Traefik/nginx LAN first in chain must not win over a real client later/as X-Real-IP."""
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


def test_client_ip_probe_exposes_three_sources():
    from app.request_client_ip import client_ip_probe

    probe = client_ip_probe(
        _req(
            headers={
                "X-Real-IP": "203.0.113.1",
                "X-Forwarded-For": "203.0.113.1, 172.24.0.108",
            },
            host="172.24.0.108",
        )
    )
    assert probe["x_real_ip"] == "203.0.113.1"
    assert probe["x_forwarded_for"] == "203.0.113.1, 172.24.0.108"
    assert probe["request_client_host"] == "172.24.0.108"
    assert probe["resolved"] == "203.0.113.1"
    assert probe["resolved_is_infra"] is False


def test_falls_back_to_x_real_ip():
    assert client_ip_from_request(_req(headers={"X-Real-IP": "10.1.2.3"})) == "10.1.2.3"


def test_falls_back_to_peer():
    assert client_ip_from_request(_req(headers={}, host="10.0.0.9")) == "10.0.0.9"


def test_x_real_ip_preferred_over_tcp_peer():
    """Regression: session capture must not use request.client.host alone."""
    ip = client_ip_from_request(
        _req(headers={"X-Real-IP": "203.0.113.50"}, host="172.24.0.108")
    )
    assert ip == "203.0.113.50"
    assert ip != "172.24.0.108"


def test_prefer_client_ip_upgrades_infra():
    assert prefer_client_ip("172.24.0.108", "192.168.2.10") == "192.168.2.10"
    assert prefer_client_ip("192.168.2.10", "172.24.0.108") == "192.168.2.10"
    assert is_infra_hop("172.24.0.108")
    assert not is_infra_hop("192.168.2.10")
