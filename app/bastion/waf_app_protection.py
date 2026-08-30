"""Per-app effective ModSecurity protection (nginx reality, not DB intent).

A shield is warranted only when traffic to that app is actually inspected:
connector ``modsecurity on`` for the family **and** SecRuleEngine On/DetectionOnly
in the live nginx snapshot. SSO Gate apps are never marked — no bastion proxy.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.access_modes import normalize_access_mode
from app.bastion.nginx_waf_export import MODE_DETECTION, MODE_ON
from app.bastion.nginx_waf_reality import (
    family_engine_mode,
    read_nginx_waf_reality,
)
from app.bastion.waf_reactivation import (
    portal_switch_export_path,
    public_switch_export_path,
    subdomain_switch_export_path,
)
from app.sso_settings import Settings

_CONNECTOR_ON_RE = re.compile(
    r"^\s*modsecurity\s+on\s*;", re.IGNORECASE | re.MULTILINE
)

_FAMILY_SWITCH_PATH = {
    "portal": portal_switch_export_path,
    "subdomain": subdomain_switch_export_path,
    "public": public_switch_export_path,
}

_MODE_LABEL = {
    MODE_ON: "blocage",
    MODE_DETECTION: "DetectionOnly",
}


def access_mode_waf_family(access_mode: str | None) -> str | None:
    """Nginx ModSecurity family that inspects this access mode, or None."""
    mode = normalize_access_mode(access_mode)
    if mode == "subdomain_proxy":
        return "subdomain"
    if mode == "public_proxy":
        return "public"
    if mode == "legacy_path_proxy":
        return "portal"
    return None


def read_family_connector_on(settings: Settings, family: str) -> bool:
    """True when the synced switch export enables the ModSecurity connector."""
    resolver = _FAMILY_SWITCH_PATH.get(family)
    if resolver is None:
        return False
    path: Path = resolver(settings)
    if not path.is_file():
        return False
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    return bool(_CONNECTOR_ON_RE.search(text))


def family_protection_effective(
    settings: Settings,
    family: str,
    *,
    active: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Effective CRS inspection for one nginx family (fail closed)."""
    reality = active if active is not None else read_nginx_waf_reality(settings=settings)
    if not reality.get("verifiable") or reality.get("stale"):
        return {
            "protected": False,
            "family": family,
            "reason": "snapshot_unusable",
            "mode": None,
        }
    engine = family_engine_mode(reality, family)
    if engine not in (MODE_ON, MODE_DETECTION):
        return {
            "protected": False,
            "family": family,
            "reason": "engine_off",
            "mode": engine,
        }
    if not read_family_connector_on(settings, family):
        return {
            "protected": False,
            "family": family,
            "reason": "connector_off",
            "mode": engine,
        }
    label = _MODE_LABEL.get(engine, engine)
    return {
        "protected": True,
        "family": family,
        "reason": "ok",
        "mode": engine,
        "title": f"WAF ModSecurity actif ({label})",
    }


def app_waf_protection(
    app: Any,
    settings: Settings,
    *,
    active: dict[str, Any] | None = None,
    family_cache: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Whether this app currently has effective ModSecurity coverage."""
    if not getattr(app, "enabled", False):
        return {
            "protected": False,
            "family": None,
            "reason": "app_disabled",
            "mode": None,
        }
    family = access_mode_waf_family(getattr(app, "access_mode", None))
    if family is None:
        return {
            "protected": False,
            "family": None,
            "reason": "no_proxy_family",
            "mode": None,
            "title": "Hors proxy bastion — WAF non applicable",
        }
    if family_cache is not None and family in family_cache:
        return dict(family_cache[family])
    status = family_protection_effective(settings, family, active=active)
    if family_cache is not None:
        family_cache[family] = status
    return dict(status)


def apps_waf_protection_by_slug(
    apps: list[Any],
    settings: Settings,
) -> dict[str, dict[str, Any]]:
    """One nginx snapshot + connector checks for the whole apps list."""
    active = read_nginx_waf_reality(settings=settings)
    family_cache: dict[str, dict[str, Any]] = {}
    out: dict[str, dict[str, Any]] = {}
    for app in apps:
        slug = getattr(app, "slug", None) or ""
        if not slug:
            continue
        out[slug] = app_waf_protection(
            app, settings, active=active, family_cache=family_cache
        )
    return out
