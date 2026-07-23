"""Nginx auth_request fragment generation for vault robotic drivers."""

from __future__ import annotations

from app.bastion.nginx_enforcement import (
    basic_auth_auth_request_lines,
    proxy_location_lines,
    wsse_auth_request_lines,
)
from app.models import App


def _app(**kwargs) -> App:
    defaults = {
        "slug": "myapp",
        "label": "My App",
        "upstream_url": "https://backend.example/",
        "access_mode": "legacy_path_proxy",
        "enabled": True,
    }
    defaults.update(kwargs)
    return App(**defaults)


def test_basic_auth_fragment():
    app = _app(auth_mode="generic_basic_auth", robotic_driver="generic_basic_auth")
    lines = basic_auth_auth_request_lines(app)
    joined = "\n".join(lines)
    assert "auth_request /internal/basic-auth-header/myapp;" in joined
    assert "proxy_set_header Authorization $robotic_auth;" in joined
    assert "X-WSSE" not in joined


def test_wsse_fragment_both_headers():
    app = _app(auth_mode="generic_wsse", robotic_driver="generic_wsse")
    lines = wsse_auth_request_lines(app)
    joined = "\n".join(lines)
    assert "auth_request /internal/wsse-header/myapp;" in joined
    assert "auth_request_set $wsse_auth $upstream_http_x_wsse_authorization;" in joined
    assert "proxy_set_header X-WSSE $wsse_auth;" in joined
    assert 'proxy_set_header Authorization \'WSSE profile="UsernameToken"\';' in joined


def test_wsse_proxy_location_includes_fragment():
    app = _app(auth_mode="generic_wsse", robotic_driver="generic_wsse")
    block = "\n".join(proxy_location_lines(app))
    assert "auth_request /internal/wsse-header/myapp;" in block
    assert "proxy_set_header X-WSSE $wsse_auth;" in block
    assert 'WSSE profile="UsernameToken"' in block


def test_sso_gate_skips_wsse_fragment():
    app = _app(
        auth_mode="generic_wsse",
        robotic_driver="generic_wsse",
        access_mode="sso_gate",
    )
    assert wsse_auth_request_lines(app) == []
