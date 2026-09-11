"""Tests for declarative M2M policy (no product-name heuristics)."""

from __future__ import annotations

from types import SimpleNamespace

from app.bastion.m2m_policy import (
    authorization_scheme,
    m2m_credential_allows,
    m2m_flags_for,
    nginx_location_specs,
    normalize_bypass_paths,
    uri_matches_bypass,
    validate_bypass_path,
)


def test_validate_bypass_path_rejects_root_and_wildcards():
    assert validate_bypass_path("/") is None
    assert validate_bypass_path("/api/*") is None
    assert validate_bypass_path("/ok") == "/ok"
    assert validate_bypass_path("/api/") == "/api/"


def test_normalize_bypass_paths_from_textarea():
    paths, errs = normalize_bypass_paths("/webhook\n/api/\n/\nbad*")
    assert "/webhook" in paths
    assert "/api/" in paths
    assert "/" not in paths
    assert errs


def test_uri_matches_bypass_exact_and_prefix():
    paths = ["/sonarqube-webhook", "/api/"]
    assert uri_matches_bypass("/sonarqube-webhook", paths)
    assert uri_matches_bypass("/sonarqube-webhook/", paths)
    assert uri_matches_bypass("/api/ce/submit", paths)
    assert not uri_matches_bypass("/projects", paths)


def test_m2m_flags_cleared_outside_subdomain_proxy():
    flags = m2m_flags_for(
        "sso_gate",
        m2m_accept_basic=True,
        m2m_bypass_paths=["/api/"],
        m2m_bypass_long_timeout=True,
    )
    assert flags["m2m_accept_basic"] is False
    assert flags["m2m_bypass_paths"] is None
    assert flags["m2m_bypass_long_timeout"] is False


def test_m2m_credential_allows():
    app = SimpleNamespace(m2m_accept_basic=True, m2m_accept_bearer=False)
    assert m2m_credential_allows(app, "Basic dXNlcjpwYXNz") == "m2m-basic"
    assert m2m_credential_allows(app, "Bearer tok") is None
    app.m2m_accept_bearer = True
    assert m2m_credential_allows(app, "Bearer tok") == "m2m-bearer"
    assert authorization_scheme("Basic ") is None


def test_nginx_location_specs():
    specs = nginx_location_specs(["/hook", "/api/"])
    assert ("= /hook", "exact") in specs
    assert ("= /hook/", "exact") in specs
    assert ("^~ /api/", "prefix") in specs
