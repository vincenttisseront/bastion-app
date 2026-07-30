"""Minimal driver registry — single source of truth for driver_name → driver.

Introduced with the provisioning module (spec Tâche 3.1) so the driver-name
dispatch is never duplicated as a second hardcoded if/elif:
- provisioning dispatch uses PROVISIONING_DRIVERS below;
- the robotic cookie-SSO dispatch in app/robotic/impersonate_service.py uses the
  same dict-lookup pattern (_COOKIE_SSO_HANDLERS) instead of its former if/elif.

V1 provisioning drivers: crushftp + generic (explicit no-op). Grafana/Wiki.js
are empty placeholders in this repo (audit §2.1) — separate future workstream.
"""

from __future__ import annotations

from app.bastion.drivers.base_provisioning import AccountProvisioningDriver
from app.bastion.drivers.crushftp import CrushFTPProvisioningDriver
from app.bastion.drivers.generic import GenericNoOpProvisioningDriver

PROVISIONING_DRIVERS: dict[str, AccountProvisioningDriver] = {
    "crushftp": CrushFTPProvisioningDriver(),
    "generic": GenericNoOpProvisioningDriver(),
}


def get_provisioning_driver(driver_name: str | None) -> AccountProvisioningDriver | None:
    """Resolve an App.provisioning_driver value; None when unset/unknown."""
    name = (driver_name or "").strip().lower()
    if not name:
        return None
    return PROVISIONING_DRIVERS.get(name)
