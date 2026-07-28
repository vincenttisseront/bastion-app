"""Export consolidated ACME domain list for the acme-companion sidecar.

All bastion-fronted FQDNs: portal + subdomain_proxy + public_proxy.
TLS on :8443 terminates here then hops to :8080 (same Host / auth logic).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.bastion.nginx_known_hosts_export import normalize_hostname
from app.bastion.nginx_public_proxy_export import iter_public_proxy_apps
from app.bastion.nginx_subdomain_export import iter_subdomain_proxy_apps
from app.sso_settings import Settings

_FAMILY_ORDER = {"portal": 0, "subdomain_proxy": 1, "public_proxy": 2}


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
