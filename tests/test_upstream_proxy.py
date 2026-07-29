"""Unit tests for upstream_origin (nginx proxy_pass path stripping)."""

from __future__ import annotations

import pytest

from app.bastion.upstream_proxy import upstream_origin


def test_upstream_origin_strips_path():
    assert upstream_origin("https://10.0.0.50/web/") == "https://10.0.0.50"
    assert upstream_origin("https://mail:8443/web") == "https://mail:8443"
    assert upstream_origin("http://backend.local/") == "http://backend.local"


def test_upstream_origin_rejects_invalid():
    with pytest.raises(ValueError):
        upstream_origin("/web/")
    with pytest.raises(ValueError):
        upstream_origin("")
