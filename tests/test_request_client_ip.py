"""Unit tests for client IP extraction from proxy headers."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.request_client_ip import client_ip_from_request


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


def test_falls_back_to_x_real_ip():
    assert client_ip_from_request(_req(headers={"X-Real-IP": "10.1.2.3"})) == "10.1.2.3"


def test_falls_back_to_peer():
    assert client_ip_from_request(_req(headers={}, host="10.0.0.9")) == "10.0.0.9"
