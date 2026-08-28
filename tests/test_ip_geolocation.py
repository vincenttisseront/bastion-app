"""Tests for ip-api.com geolocation integration."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.bastion.ip_geolocation import (
    clear_geoloc_state_for_tests,
    country_flag,
    is_public_ip,
    lookup_ip_origins,
    origin_from_geoloc,
)
from app.sso_settings import Settings


@pytest.fixture(autouse=True)
def _reset_geoloc():
    clear_geoloc_state_for_tests()
    yield
    clear_geoloc_state_for_tests()


def test_country_flag_from_iso_code():
    assert country_flag("FR") == "🇫🇷"
    assert country_flag("us") == "🇺🇸"
    assert country_flag("") == "🌐"


def test_is_public_ip_filters_private():
    assert is_public_ip("8.8.8.8")
    assert not is_public_ip("127.0.0.1")
    assert not is_public_ip("10.0.0.1")
    assert not is_public_ip("")


def test_origin_from_geoloc_success():
    geo = {
        "status": "success",
        "country": "France",
        "countryCode": "FR",
        "city": "Paris",
        "regionName": "Île-de-France",
        "isp": "Orange",
        "query": "90.90.90.90",
    }
    origin = origin_from_geoloc("90.90.90.90", geo)
    assert origin["flag"] == "🇫🇷"
    assert "Paris" in origin["hint"]
    assert "France" in origin["hint"]


@respx.mock
def test_lookup_ip_origins_batch_and_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("PORTAL_DATA_DIR", str(tmp_path / "data"))
    settings = Settings(
        portal_domain="portal.example.fr",
        ip_geoloc_enabled=True,
        ip_geoloc_base_url="http://ip-api.com",
        ip_geoloc_lang="fr",
    )  # type: ignore[call-arg]

    route = respx.post(url__regex=r"http://ip-api\.com/batch.*").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "status": "success",
                    "country": "France",
                    "countryCode": "FR",
                    "city": "Paris",
                    "regionName": "Île-de-France",
                    "isp": "Test ISP",
                    "query": "34.155.98.34",
                }
            ],
            headers={"X-Rl": "14", "X-Ttl": "60"},
        )
    )

    first = lookup_ip_origins(settings, ["34.155.98.34"])
    assert route.call_count == 1
    assert first["34.155.98.34"]["country"] == "France"

    second = lookup_ip_origins(settings, ["34.155.98.34"])
    assert route.call_count == 1
    assert second["34.155.98.34"]["countryCode"] == "FR"

    cache_file = tmp_path / "data" / "cache" / "ip-geoloc-v1.json"
    assert cache_file.is_file()
    cached = json.loads(cache_file.read_text(encoding="utf-8"))
    assert "34.155.98.34" in cached["entries"]


@respx.mock
def test_lookup_skips_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("PORTAL_DATA_DIR", str(tmp_path / "data"))
    settings = Settings(
        portal_domain="portal.example.fr",
        ip_geoloc_enabled=False,
    )  # type: ignore[call-arg]
    route = respx.post(url__regex=r"http://ip-api\.com/batch.*").mock(
        return_value=httpx.Response(200, json=[])
    )
    assert lookup_ip_origins(settings, ["8.8.8.8"]) == {}
    assert route.call_count == 0
