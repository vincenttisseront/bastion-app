"""Health probe unit and integration tests."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx
from httpx import Response
from sqlalchemy.orm import Session

from app.health_probe import (
    classify_http_status,
    probe_all_enabled_apps,
    probe_application,
    probe_application_result,
    probe_target_url,
)
from app.models import App

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (200, "ok"),
        (302, "ok"),
        (401, "ok"),
        (403, "ok"),
        (404, "warn"),
        (500, "error"),
    ],
)
def test_classify_http_status(code, expected):
    assert classify_http_status(code) == expected


@pytest.mark.asyncio
async def test_probe_application_no_url():
    app = SimpleNamespace(upstream_url="", healthcheck_url=None)
    result = await probe_application(app)
    assert result["status"] == "error"
    assert result["error"]


@pytest.mark.asyncio
@respx.mock
async def test_probe_application_ok():
    app = SimpleNamespace(
        upstream_url="https://transfer.example.fr/",
        healthcheck_url=None,
        public_fqdn=None,
        upstream_tls_verify=False,
    )
    respx.get("https://transfer.example.fr/").mock(return_value=Response(200))
    result = await probe_application(app)
    assert result["status"] == "ok"
    assert result["http_code"] == 200
    assert result["latency_ms"] is not None


@pytest.mark.asyncio
@respx.mock
async def test_probe_application_auth_challenge_is_ok():
    app = SimpleNamespace(
        upstream_url="https://wiki.example.fr/",
        healthcheck_url=None,
        public_fqdn=None,
        upstream_tls_verify=False,
    )
    respx.get("https://wiki.example.fr/").mock(return_value=Response(401))
    result = await probe_application(app)
    assert result["status"] == "ok"
    assert result["http_code"] == 401


@pytest.mark.asyncio
@respx.mock
async def test_probe_application_error_5xx():
    app = SimpleNamespace(
        upstream_url="https://app.example.fr/",
        healthcheck_url=None,
        public_fqdn=None,
        upstream_tls_verify=False,
    )
    respx.get("https://app.example.fr/").mock(return_value=Response(503))
    result = await probe_application(app)
    assert result["status"] == "error"
    assert result["http_code"] == 503


@pytest.mark.asyncio
@respx.mock
async def test_probe_application_timeout():
    app = SimpleNamespace(
        upstream_url="https://slow.example.fr/",
        healthcheck_url=None,
        public_fqdn=None,
        upstream_tls_verify=False,
    )
    respx.get("https://slow.example.fr/").mock(side_effect=httpx.ReadTimeout("timeout"))
    result = await probe_application(app)
    assert result["status"] == "error"
    assert "Timeout" in result["error"]


@pytest.mark.asyncio
@respx.mock
async def test_probe_application_connection_error():
    app = SimpleNamespace(
        upstream_url="https://missing.example.fr/",
        healthcheck_url=None,
        public_fqdn=None,
        upstream_tls_verify=False,
    )
    respx.get("https://missing.example.fr/").mock(side_effect=httpx.ConnectError("dns"))
    result = await probe_application(app)
    assert result["status"] == "error"
    assert "Injoignable" in result["error"]


@pytest.mark.asyncio
async def test_probe_uses_app_tls_verify_default_false():
    app = SimpleNamespace(
        id=1,
        upstream_url="https://10.0.0.50/",
        healthcheck_url=None,
        public_fqdn="webmail.example.fr",
        upstream_tls_verify=False,
    )
    mock_resp = MagicMock(status_code=200)
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("app.health_probe.httpx.AsyncClient", return_value=mock_client) as client_cls:
        result = await probe_application_result(app)

    assert result.overall_status.value == "ok"
    kwargs = client_cls.call_args.kwargs
    assert kwargs["verify"] is False
    mock_client.get.assert_awaited_once()
    call_kwargs = mock_client.get.await_args
    assert call_kwargs.args[0] == "https://10.0.0.50/"
    assert call_kwargs.kwargs["headers"] == {"Host": "webmail.example.fr"}


@pytest.mark.asyncio
async def test_probe_respects_tls_verify_true():
    app = SimpleNamespace(
        id=2,
        upstream_url="https://secure.example.fr/",
        healthcheck_url=None,
        public_fqdn=None,
        upstream_tls_verify=True,
    )
    mock_resp = MagicMock(status_code=200)
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("app.health_probe.httpx.AsyncClient", return_value=mock_client) as client_cls:
        await probe_application_result(app)

    assert client_cls.call_args.kwargs["verify"] is True


@pytest.mark.asyncio
async def test_probe_all_never_raises(db_session: Session):
    db_session.add(
        App(
            slug="good",
            label="Good",
            upstream_url="https://good.example.fr/",
            enabled=True,
            probe_enabled=True,
        )
    )
    db_session.add(
        App(
            slug="bad",
            label="Bad",
            upstream_url="https://bad.example.fr/",
            enabled=True,
            probe_enabled=True,
        )
    )
    db_session.commit()

    async def flaky_probe(app):
        if app.slug == "bad":
            raise RuntimeError("boom")
        return {"status": "ok", "http_code": 200, "latency_ms": 10, "error": None}

    with patch("app.health_probe.probe_application", side_effect=flaky_probe):
        summary = await probe_all_enabled_apps(db_session)

    assert "status_counts" in summary
    assert summary["status_counts"]["ok"] >= 1


def test_probe_single_endpoint(client, db_session: Session):
    app = App(
        slug="transfer",
        label="Transfer",
        upstream_url="https://transfer.example.fr/",
        enabled=True,
        probe_enabled=True,
    )
    db_session.add(app)
    db_session.commit()
    db_session.refresh(app)

    with respx.mock:
        respx.get("https://transfer.example.fr/").mock(return_value=Response(200))
        resp = client.post(f"/admin/health/probe/{app.id}", headers=ADMIN_HEADERS)

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["http_code"] == 200
    assert data["latency_ms"] is not None


def test_probe_target_url_prefers_healthcheck():
    app = SimpleNamespace(upstream_url="https://public/", healthcheck_url="https://health/")
    assert probe_target_url(app) == "https://health/"


def test_probe_target_url_strips_entry_path():
    app = SimpleNamespace(
        upstream_url="https://10.0.0.50/web",
        healthcheck_url=None,
    )
    assert probe_target_url(app) == "https://10.0.0.50/"
