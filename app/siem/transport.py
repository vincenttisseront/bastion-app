"""SIEM transport — syslog TLS and HTTPS webhook only."""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.siem.formatters import format_cef, format_ecs_json
from app.siem.settings_service import SiemForwardingConfig

logger = logging.getLogger(__name__)


class SiemDeliveryError(Exception):
    """Transient or permanent delivery failure."""


def _rfc5424_message(cef_body: str, *, hostname: str = "bastion") -> bytes:
    # PRI = facility 14 (log audit) * 8 + severity 5 (notice) → 117 — pragmatic default.
    # Second precision only: fractional seconds make some syslog predecoders (Wazuh)
    # swallow the first character of HOSTNAME into TIMESTAMP (e.g. bastion → bastio).
    host = (hostname or "bastion").strip().replace(" ", "_") or "bastion"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    msg = f"<117>1 {ts} {host} BastionPro-Sentinel - - - {cef_body}\n"
    return msg.encode("utf-8")


def deliver_syslog_tls(
    entry: dict[str, Any],
    config: SiemForwardingConfig,
    *,
    sock_factory=None,
) -> None:
    host = config.syslog_host
    port = config.syslog_port
    if not host:
        raise SiemDeliveryError("syslog_host empty")
    body = format_cef(entry)
    payload = _rfc5424_message(body)
    ctx = ssl.create_default_context()
    if not config.syslog_tls_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    def _connect():
        raw = socket.create_connection((host, port), timeout=15)
        return ctx.wrap_socket(raw, server_hostname=host if config.syslog_tls_verify else None)

    connect = sock_factory or _connect
    try:
        with connect() as sock:
            sock.sendall(payload)
    except OSError as exc:
        raise SiemDeliveryError(f"syslog_tls failed: {exc}") from exc


def deliver_webhook_https(
    entry: dict[str, Any],
    config: SiemForwardingConfig,
    *,
    secret: str | None = None,
    client: httpx.Client | None = None,
) -> None:
    url = config.webhook_url
    if not url.startswith("https://"):
        raise SiemDeliveryError("webhook_url must be https://")
    # Extra guard: reject cleartext even if misconfigured.
    if urlsplit(url).scheme != "https":
        raise SiemDeliveryError("webhook must use HTTPS")

    headers = {"Content-Type": "application/json", "User-Agent": "BastionPro-Sentinel/SIEM"}
    auth = None
    if config.webhook_auth_type == "bearer" and secret:
        headers["Authorization"] = f"Bearer {secret}"
    elif config.webhook_auth_type == "basic" and secret:
        # secret format: username:password
        if ":" in secret:
            user, pwd = secret.split(":", 1)
            auth = (user, pwd)
        else:
            auth = (secret, "")

    body = format_ecs_json(entry)
    own_client = client is None
    http = client or httpx.Client(timeout=15.0, verify=True)
    try:
        resp = http.post(url, content=body.encode("utf-8"), headers=headers, auth=auth)
        if resp.status_code >= 400:
            raise SiemDeliveryError(f"webhook HTTP {resp.status_code}: {(resp.text or '')[:200]}")
    except httpx.HTTPError as exc:
        raise SiemDeliveryError(f"webhook failed: {exc}") from exc
    finally:
        if own_client:
            http.close()


def deliver_entry(
    entry: dict[str, Any],
    config: SiemForwardingConfig,
    *,
    secret: str | None = None,
    sock_factory=None,
    http_client: httpx.Client | None = None,
) -> None:
    if config.protocol == "syslog_tls":
        deliver_syslog_tls(entry, config, sock_factory=sock_factory)
    elif config.protocol == "webhook_https":
        deliver_webhook_https(entry, config, secret=secret, client=http_client)
    else:
        raise SiemDeliveryError(f"unknown protocol {config.protocol}")
