"""Export consolidated ACME domain list for the acme-companion sidecar.

Iteration 1: public_proxy FQDNs only (portal / subdomain_proxy stay on reverse01).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.bastion.nginx_known_hosts_export import normalize_hostname
from app.bastion.nginx_public_proxy_export import iter_public_proxy_apps
from app.sso_settings import Settings


def build_acme_domains_manifest(db: Session, settings: Settings) -> dict[str, Any]:
    domains: list[dict[str, Any]] = []
    seen: set[str] = set()
    for app in iter_public_proxy_apps(db):
        fqdn = normalize_hostname(app.public_fqdn)
        if not fqdn or fqdn in seen:
            continue
        seen.add(fqdn)
        domains.append(
            {
                "fqdn": fqdn,
                "slug": app.slug,
                "family": "public_proxy",
                "upstream_url": (app.upstream_url or "").rstrip("/") + "/",
            }
        )
    return {
        "challenge": "dns-01",
        "dns_api": "dns_cf",
        "scope": "public_proxy",
        "portal_domain": normalize_hostname(settings.portal_domain),
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
