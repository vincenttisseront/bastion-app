"""Teleport agent / reverse-tunnel API paths that must bypass portal SSO.

Agents (``Go-http-client/1.1``) authenticate with Teleport directly (join
tokens, mTLS, WebSocket upgrade). They never carry portal oauth2/bastion
cookies — gating them behind ``auth_request`` yields 302 → portal login and
breaks every node agent behind the bastion subdomain vhost.
"""

from __future__ import annotations

import re

from app.models import App

# Terminal streaming over WebSocket (same as public_proxy export).
_CONNECT_WS_RE = re.compile(r"^/v[12]/webapi/.+/connect/ws(?:/|$)", re.IGNORECASE)

# Exact paths used by reverse-tunnel discovery and TLS-routing upgrade probes.
_AGENT_EXACT_PATHS = frozenset(
    {
        "/webapi/find",
        "/webapi/ping",
        "/webapi/connectionupgrade",
    }
)


def _path_only(uri: str) -> str:
    raw = (uri or "").split("?", 1)[0].strip() or "/"
    if not raw.startswith("/"):
        raw = f"/{raw}"
    return raw.rstrip("/") or "/"


def is_teleport_app(app: App | None) -> bool:
    if app is None:
        return False
    driver = (getattr(app, "robotic_driver", None) or "").strip().lower()
    provision = (getattr(app, "provisioning_driver", None) or "").strip().lower()
    return driver == "teleport" or provision == "teleport"


def is_teleport_agent_uri(uri: str) -> bool:
    """True for Teleport agent/reverse-tunnel endpoints (no portal SSO)."""
    path = _path_only(uri)
    if path in _AGENT_EXACT_PATHS:
        return True
    if path.startswith("/webapi/host/"):
        return True
    return bool(_CONNECT_WS_RE.match(path))


def is_teleport_agent_request(uri: str, app: App | None) -> bool:
    return is_teleport_app(app) and is_teleport_agent_uri(uri)
