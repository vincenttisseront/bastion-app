"""Health probe unit and integration tests."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from httpx import Response
from sqlalchemy.orm import Session

from app.health_probe import (
    classify_http_status,
    probe_all_enabled_apps,
    probe_application,
    probe_target_url,
)
from app.models import App

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


@pytest.mark.parametrize(
    ("code", "expected"),
    [(200, "ok"), (302, "ok"), (401, "warn"), (404, "warn"), (500, "error")],
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
    app = SimpleNamespace(upstream_url="https://transfer.example.fr/", healthcheck_url=None)
    respx.get("https://transfer.example.fr/").mock(return_value=Response(200))
    result = await probe_application(app)
    assert result["status"] == "ok"
    assert result["http_code"] == 200
    assert result["latency_ms"] is not None


@pytest.mark.asyncio
@respx.mock
async def test_probe_application_warn_401():
    app = SimpleNamespace(upstream_url="https://wiki.example.fr/", healthcheck_url=None)
    respx.get("https://wiki.example.fr/").mock(return_value=Response(401))
    result = await probe_application(app)
    assert result["status"] == "warn"
    assert result["http_code"] == 401


@pytest.mark.asyncio
@respx.mock
async def test_probe_application_error_5xx():
    app = SimpleNamespace(upstream_url="https://app.example.fr/", healthcheck_url=None)
    respx.get("https://app.example.fr/").mock(return_value=Response(503))
    result = await probe_application(app)
    assert result["status"] == "error"
    assert result["http_code"] == 503


@pytest.mark.asyncio
@respx.mock
async def test_probe_application_timeout():
    app = SimpleNamespace(upstream_url="https://slow.example.fr/", healthcheck_url=None)
    respx.get("https://slow.example.fr/").mock(side_effect=httpx.ReadTimeout("timeout"))
    result = await probe_application(app)
    assert result["status"] == "error"
    assert "Timeout" in result["error"]


@pytest.mark.asyncio
@respx.mock
async def test_probe_application_connection_error():
    app = SimpleNamespace(upstream_url="https://missing.example.fr/", healthcheck_url=None)
    respx.get("https://missing.example.fr/").mock(side_effect=httpx.ConnectError("dns"))
    result = await probe_application(app)
    assert result["status"] == "error"
    assert "Injoignable" in result["error"]


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
