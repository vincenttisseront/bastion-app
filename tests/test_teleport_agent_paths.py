"""Teleport agent URI classification."""

from __future__ import annotations

from types import SimpleNamespace

from app.bastion.teleport_agent_paths import (
    is_teleport_agent_request,
    is_teleport_agent_uri,
    is_teleport_app,
)


def test_is_teleport_app():
    assert is_teleport_app(SimpleNamespace(robotic_driver="teleport"))
    assert not is_teleport_app(SimpleNamespace(robotic_driver="crushftp"))


def test_agent_uri_exact_paths():
    for path in (
        "/webapi/find",
        "/webapi/find?version=18",
        "/webapi/ping",
        "/webapi/connectionupgrade",
    ):
        assert is_teleport_agent_uri(path)


def test_agent_uri_host_credentials_and_ws():
    assert is_teleport_agent_uri("/webapi/host/credentials")
    assert is_teleport_agent_uri("/v1/webapi/sites/default/connect/ws")
    assert not is_teleport_agent_uri("/webapi/user/status")
    assert not is_teleport_agent_uri("/v1/webapi/sessions/web")


def test_agent_request_requires_teleport_app():
    app = SimpleNamespace(robotic_driver="teleport", provisioning_driver=None)
    assert is_teleport_agent_request("/webapi/find", app)
    assert not is_teleport_agent_request("/webapi/find", SimpleNamespace(robotic_driver="crushftp"))
