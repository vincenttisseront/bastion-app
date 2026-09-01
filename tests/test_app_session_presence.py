"""Tests for upstream session cookie presence detection."""

from __future__ import annotations

import binascii
import json

from app.models import App
from app.robotic.app_session_presence import has_app_session_cookie


def _teleport_app() -> App:
    return App(
        slug="teleport",
        robotic_driver="teleport",
        enabled=True,
    )


def test_has_app_session_cookie_teleport_requires_host_session():
    app = _teleport_app()
    session_val = binascii.hexlify(
        json.dumps({"user": "admin", "sid": "abc"}).encode()
    ).decode()
    assert has_app_session_cookie(app, f"__Host-session={session_val}")
    assert not has_app_session_cookie(app, "bastion_session=portal-only")


def test_has_app_session_cookie_crushftp_requires_crushauth():
    app = App(slug="transfer", robotic_driver="crushftp", enabled=True)
    assert has_app_session_cookie(app, "CrushAuth=1785773795018_abc")
    assert not has_app_session_cookie(app, "bastion_session=only-portal")
