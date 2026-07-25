"""Shared fixtures for light active security probes against staging."""

from __future__ import annotations

import os

import pytest

# Confirmed by Vincent 2026-07-25: portal.ar-systems.fr → 172.24.0.108 (nginx)
# fronting portal Docker on 172.24.0.110 — staging/test path, not production.
STAGING_BASE_URL = os.environ.get(
    "BASTION_SECURITY_BASE_URL",
    "https://portal.ar-systems.fr",
).rstrip("/")

EXPECTED_STAGING_IP = os.environ.get("BASTION_SECURITY_EXPECTED_IP", "172.24.0.108")


@pytest.fixture(scope="session")
def staging_base_url() -> str:
    return STAGING_BASE_URL


@pytest.fixture(scope="session")
def expected_staging_ip() -> str:
    return EXPECTED_STAGING_IP
