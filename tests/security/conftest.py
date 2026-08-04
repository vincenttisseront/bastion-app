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

# Active probes hit the LIVE portal (network calls + audit noise: every full
# pytest run used to leave breakglass.login_failed 'audit-probe-nonexistent'
# rows and ALERTE entries in Admin → Logs). Opt-in only.
RUN_ACTIVE_PROBES = os.environ.get("BASTION_SECURITY_ACTIVE", "") in ("1", "true", "yes")


def pytest_collection_modifyitems(config, items):
    if RUN_ACTIVE_PROBES:
        return
    skip = pytest.mark.skip(
        reason=(
            "sonde active contre le portail live — lancez avec "
            "BASTION_SECURITY_ACTIVE=1 pour l'exécuter"
        )
    )
    for item in items:
        if item.get_closest_marker("security_active"):
            item.add_marker(skip)


@pytest.fixture(scope="session")
def staging_base_url() -> str:
    return STAGING_BASE_URL


@pytest.fixture(scope="session")
def expected_staging_ip() -> str:
    return EXPECTED_STAGING_IP
