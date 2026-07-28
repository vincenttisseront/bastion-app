"""ACME domains export — all bastion FQDNs."""

from __future__ import annotations

import json
from pathlib import Path

from app.bastion.acme_domains_export import (
    build_acme_domains_manifest,
    write_acme_domains_export,
)
from app.models import App
from app.sso_settings import Settings


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        portal_domain="portal.example.fr",
        sso_portal_default_realm_slug="ar-systems",
        exports_dir=str(tmp_path / "exports"),
        vault_portal_internal_token="test-secret",
    )  # type: ignore[call-arg]


def test_acme_domains_manifest_includes_all_families(db_session, tmp_path):
    settings = _settings(tmp_path)
    db_session.add(
        App(
            slug="teleport",
            label="Teleport",
            upstream_url="https://10.0.31.103/",
            access_mode="public_proxy",
            public_fqdn="teleport.ar-systems.fr",
            enabled=True,
        )
    )
    db_session.add(
        App(
            slug="doli",
            label="Doli",
            upstream_url="https://10.0.0.1/",
            access_mode="subdomain_proxy",
            public_fqdn="dolibarr.ar-systems.fr",
            enabled=True,
        )
    )
    db_session.commit()

    manifest = build_acme_domains_manifest(db_session, settings)
    assert manifest["challenge"] == "dns-01"
    assert manifest["scope"] == "all_bastion_hosts"
    by_family = {d["family"]: d["fqdn"] for d in manifest["domains"]}
    assert by_family["portal"] == "portal.example.fr"
    assert by_family["subdomain_proxy"] == "dolibarr.ar-systems.fr"
    assert by_family["public_proxy"] == "teleport.ar-systems.fr"
    fqdns = [d["fqdn"] for d in manifest["domains"]]
    assert fqdns == [
        "portal.example.fr",
        "dolibarr.ar-systems.fr",
        "teleport.ar-systems.fr",
    ]


def test_write_acme_domains_export(tmp_path, db_session):
    settings = _settings(tmp_path)
    db_session.add(
        App(
            slug="status",
            label="Status",
            upstream_url="http://10.0.0.2/",
            access_mode="public_proxy",
            public_fqdn="status.example.fr",
            enabled=True,
        )
    )
    db_session.commit()
    path = write_acme_domains_export(db_session, settings)
    assert path.name == "acme-domains.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    fqdns = {d["fqdn"] for d in data["domains"]}
    assert "portal.example.fr" in fqdns
    assert "status.example.fr" in fqdns


def test_acme_scripts_exist_and_no_certs_committed():
    root = Path(__file__).resolve().parents[1]
    assert (root / "docker/acme/reconcile-certs.sh").is_file()
    assert (root / "docker/acme/entrypoint-acme.sh").is_file()
    assert (root / "docker/nginx/sync-acme-tls.sh").is_file()
    assert (root / "docker/nginx/sync-public-proxy-tls.sh").is_file()
    assert (root / ".env.acme.example").is_file()
    assert not (root / ".env.acme").exists()
