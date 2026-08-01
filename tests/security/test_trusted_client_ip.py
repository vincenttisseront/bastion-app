"""Trusted client-IP chain — break-glass / RFC1918 must not trust spoofed headers."""

from __future__ import annotations

from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth import is_rfc1918
from app.breakglass_store import set_breakglass_password
from app.models import AuditLog
from app.request_client_ip import client_ip_from_request
from app.sso_settings import get_settings
from app.subdomain.subdomain_auth import subdomain_auth
from tests.test_auth_login_flow import _add_default_idp


def _req(*, headers: dict, host: str):
    request = MagicMock()
    request.headers = headers
    request.client = MagicMock(host=host)
    return request


def test_direct_fastapi_spoofed_rfc1918_xff_is_external():
    """Bypass nginx: spoofed private XFF must not look LAN."""
    ip = client_ip_from_request(
        _req(
            headers={
                "X-Forwarded-For": "10.0.0.50, 172.24.0.108",
                "X-Real-IP": "10.0.0.50",
                "CF-Connecting-IP": "192.168.0.1",
            },
            host="198.51.100.10",
        )
    )
    assert ip == "198.51.100.10"
    settings = get_settings()
    assert not is_rfc1918(ip, settings.rfc1918_cidrs)


def test_trusted_proxy_public_xff_is_external():
    ip = client_ip_from_request(
        _req(
            headers={"X-Forwarded-For": "203.0.113.77", "X-Real-IP": "203.0.113.77"},
            host="10.5.0.2",
        )
    )
    assert ip == "203.0.113.77"
    settings = get_settings()
    assert not is_rfc1918(ip, settings.rfc1918_cidrs)


def test_trusted_proxy_lan_xff_is_rfc1918():
    ip = client_ip_from_request(
        _req(
            headers={"X-Forwarded-For": "192.168.1.50", "X-Real-IP": "192.168.1.50"},
            host="10.5.0.2",
        )
    )
    assert ip == "192.168.1.50"
    settings = get_settings()
    assert is_rfc1918(ip, settings.rfc1918_cidrs)


def test_trusted_proxy_corp_172_24_lan_is_rfc1918():
    """Same /16 as reverse01 but not .108 — real workstation."""
    ip = client_ip_from_request(
        _req(
            headers={"X-Real-IP": "172.24.0.50", "X-Forwarded-For": "172.24.0.50"},
            host="10.5.0.2",
        )
    )
    assert ip == "172.24.0.50"
    assert is_rfc1918(ip, get_settings().rfc1918_cidrs)


def test_reverse01_never_resolved_as_client():
    ip = client_ip_from_request(
        _req(
            headers={
                "X-Real-IP": "172.24.0.108",
                "X-Forwarded-For": "172.24.0.108",
            },
            host="10.5.0.2",
        )
    )
    assert ip != "172.24.0.108"
    assert ip == ""
    settings = get_settings()
    assert not is_rfc1918(ip, settings.rfc1918_cidrs)


def test_breakglass_rejected_when_only_reverse_ip_visible(
    client: TestClient, db_session: Session
):
    """Misconfigured chain (X-Real-IP=reverse01) must not open break-glass."""
    _add_default_idp(db_session)
    set_breakglass_password(db_session, "admin", "super-secret-password")

    response = client.post(
        "/auth/breakglass",
        data={
            "username": "admin",
            "password": "super-secret-password",
            "rd": "/dashboard",
        },
        headers={"X-Real-IP": "172.24.0.108", "X-Forwarded-For": "172.24.0.108"},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "bg_session" not in response.cookies
    denied = (
        db_session.query(AuditLog)
        .filter_by(action="breakglass.login_denied_non_lan")
        .count()
    )
    assert denied >= 1


def test_breakglass_rejected_on_header_spoof_from_untrusted_logic():
    """Unit: untrusted peer + spoofed LAN headers → not RFC1918 for access control."""
    ip = client_ip_from_request(
        _req(
            headers={"X-Real-IP": "10.0.0.1", "X-Forwarded-For": "10.0.0.1"},
            host="203.0.113.10",
        )
    )
    assert ip == "203.0.113.10"
    assert not is_rfc1918(ip, get_settings().rfc1918_cidrs)


def test_contradictory_spoof_headers_prefer_x_real_when_trusted():
    ip = client_ip_from_request(
        _req(
            headers={
                "X-Forwarded-For": "10.0.0.1, 203.0.113.5",
                "X-Real-IP": "203.0.113.9",
                "CF-Connecting-IP": "192.168.9.9",
                "True-Client-IP": "10.9.9.9",
                "X-Client-IP": "172.16.0.9",
            },
            host="10.5.0.2",
        )
    )
    assert ip == "203.0.113.9"


def test_subdomain_rfc1918_ignores_spoof_from_untrusted_peer(db_session: Session, monkeypatch):
    """F-04: direct call with spoofed private X-Real-IP must not bypass."""
    from app.sso_settings import Settings

    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
        rfc1918_bypass_enabled=True,
        environment="test",
        session_hop_secret="test-session-hop-secret-for-pytest",
    )

    request = _req(
        headers={
            "X-Original-Host": "transfer.example.test",
            "X-Real-IP": "10.0.0.50",
        },
        host="203.0.113.55",
    )

    import asyncio

    resp = asyncio.run(subdomain_auth(request, db=db_session, settings=settings))
    assert resp.headers.get("X-Auth-Source") != "rfc1918-bypass"
    assert resp.status_code in (401, 403)
