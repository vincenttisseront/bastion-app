"""Export consolidated ACME domain list for the acme-companion sidecar.

All edge FQDNs: portal + subdomain_proxy + public_proxy + infra (Keycloak, …).
TLS on :443 terminates here then hops to :8080 (same Host / auth or infra proxy).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.bastion.nginx_known_hosts_export import normalize_hostname
from app.bastion.nginx_public_proxy_export import iter_public_proxy_apps
from app.bastion.nginx_subdomain_export import iter_subdomain_proxy_apps
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

_FAMILY_ORDER = {
    "portal": 0,
    "subdomain_proxy": 1,
    "public_proxy": 2,
    "infra": 3,
}


def _load_infra_domains(settings: Settings) -> list[dict[str, Any]]:
    """FQDNs from Ansible export exports/infra-acme-domains.json (Keycloak, …)."""
    path = Path(settings.exports_dir) / "infra-acme-domains.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("acme: cannot read infra-acme-domains.json: %s", exc)
        return []
    if not isinstance(data, list):
        return []
    out: list[dict[str, Any]] = []
    for row in data:
        if not isinstance(row, dict):
            continue
        fqdn = normalize_hostname(str(row.get("fqdn") or ""))
        if not fqdn:
            continue
        out.append(
            {
                "fqdn": fqdn,
                "slug": str(row.get("slug") or fqdn.split(".")[0] or "infra"),
                "family": "infra",
                "upstream_url": str(row.get("upstream_url") or ""),
            }
        )
    return out


def build_acme_domains_manifest(db: Session, settings: Settings) -> dict[str, Any]:
    domains: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(
        *,
        fqdn: str | None,
        slug: str,
        family: str,
        upstream_url: str = "",
    ) -> None:
        host = normalize_hostname(fqdn)
        if not host or host in seen:
            return
        seen.add(host)
        domains.append(
            {
                "fqdn": host,
                "slug": slug,
                "family": family,
                "upstream_url": (upstream_url or "").rstrip("/") + "/"
                if upstream_url
                else "",
            }
        )

    portal = normalize_hostname(settings.portal_domain)
    _add(fqdn=portal, slug="portal", family="portal")

    for app in iter_subdomain_proxy_apps(db):
        _add(
            fqdn=app.public_fqdn,
            slug=app.slug,
            family="subdomain_proxy",
            upstream_url=app.upstream_url or "",
        )

    for app in iter_public_proxy_apps(db):
        _add(
            fqdn=app.public_fqdn,
            slug=app.slug,
            family="public_proxy",
            upstream_url=app.upstream_url or "",
        )

    for row in _load_infra_domains(settings):
        _add(
            fqdn=row["fqdn"],
            slug=row["slug"],
            family="infra",
            upstream_url=row.get("upstream_url") or "",
        )

    domains.sort(key=lambda d: (_FAMILY_ORDER.get(d["family"], 9), d["fqdn"]))
    return {
        "challenge": "dns-01",
        "dns_api": "dns_cf",
        "scope": "all_bastion_hosts",
        "portal_domain": portal,
        "domains": domains,
    }


def write_acme_domains_export(db: Session, settings: Settings) -> Path:
    exports = Path(settings.exports_dir)
    exports.mkdir(parents=True, exist_ok=True)
    path = exports / "acme-domains.json"
    manifest = build_acme_domains_manifest(db, settings)
    path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path
