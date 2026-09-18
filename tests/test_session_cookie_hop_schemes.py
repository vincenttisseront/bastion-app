"""Unit checks for session-cookie hop scheme probes."""

from __future__ import annotations

from app.robotic.session_cookie_hop import _SCHEME_HTTP, _SCHEME_HTTPS


def test_scheme_constants_are_probes_not_endpoints():
    assert _SCHEME_HTTPS == "https://"
    assert _SCHEME_HTTP == "http://"
    assert "https://app.example.com".startswith(_SCHEME_HTTPS)
    assert "http://10.0.0.10".startswith(_SCHEME_HTTP)
    assert not "https://app.example.com".startswith(_SCHEME_HTTP)
