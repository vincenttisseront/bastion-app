"""MTA-STS policy build, nginx export, ACME domain wiring."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.bastion.acme_domains_export import build_acme_domains_manifest
from app.bastion.nginx_known_hosts_export import collect_known_hostnames
from app.mail.mta_sts_service import (
    build_policy_text,
    generate_nginx_mta_sts_conf,
    parse_mx_hosts,
    update_mta_sts_settings,
    validate_mail_domain,
    write_mta_sts_nginx_export,
)
from app.sso_settings import Settings


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        portal_domain="portal.example.fr",
        sso_portal_default_realm_slug="ar-systems",
        exports_dir=str(tmp_path / "exports"),
        vault_portal_internal_token="test-secret",
    )  # type: ignore[call-arg]


def test_parse_mx_strips_url_junk():
    hosts = parse_mx_hosts("://mail.exemple.fr\nhttps://mx2.exemple.fr/path\n*.exemple.fr")
    assert hosts == ["mail.exemple.fr", "mx2.exemple.fr", "*.exemple.fr"]


def test_validate_mail_domain_rejects_mta_sts_prefix():
    with pytest.raises(ValueError):
        validate_mail_domain("mta-sts.ar-systems.fr")
    assert validate_mail_domain("ar-systems.fr") == "ar-systems.fr"


def test_build_policy_text_rfc_shape():
    text = build_policy_text(
        mode="testing",
        mx_hosts=["mail.ar-systems.fr", "*.ar-systems.fr"],
        max_age=604800,
    )
    assert text == (
        "version: STSv1\n"
        "mode: testing\n"
        "mx: mail.ar-systems.fr\n"
        "mx: *.ar-systems.fr\n"
        "max_age: 604800\n"
    )


def test_generate_nginx_conf_serves_well_known():
    conf = generate_nginx_mta_sts_conf(
        enabled=True,
        mail_domain="ar-systems.fr",
        mode="enforce",
        mx_hosts=["mail.ar-systems.fr"],
        max_age=604800,
    )
    assert "server_name mta-sts.ar-systems.fr;" in conf
    assert "location = /.well-known/mta-sts.txt" in conf
    assert "mode: enforce" in conf
    assert "mx: mail.ar-systems.fr" in conf


def test_generate_nginx_conf_disabled_is_comment_only():
    conf = generate_nginx_mta_sts_conf(
        enabled=False,
        mail_domain=None,
        mode="testing",
        mx_hosts=[],
        max_age=604800,
    )
    assert "server {" not in conf
    assert "MTA-STS disabled" in conf


def test_update_writes_export_and_acme(db_session, tmp_path):
    settings = _settings(tmp_path)
    update_mta_sts_settings(
        db_session,
        settings,
        actor="admin@test",
        enabled=True,
        mail_domain="ar-systems.fr",
        mode="testing",
        mx_hosts="mail.ar-systems.fr\n*.ar-systems.fr",
        max_age=604800,
    )
    path = Path(settings.exports_dir) / "nginx-mta-sts.conf"
    assert path.is_file()
    body = path.read_text(encoding="utf-8")
    assert "mta-sts.ar-systems.fr" in body
    assert "mode: testing" in body

    manifest = build_acme_domains_manifest(db_session, settings)
    fqdns = {d["fqdn"] for d in manifest["domains"]}
    assert "mta-sts.ar-systems.fr" in fqdns
    families = {d["fqdn"]: d["family"] for d in manifest["domains"]}
    assert families["mta-sts.ar-systems.fr"] == "mta_sts"

    known = collect_known_hostnames(db_session, settings)
    assert "mta-sts.ar-systems.fr" in known


def test_write_export_when_disabled(db_session, tmp_path):
    settings = _settings(tmp_path)
    path = write_mta_sts_nginx_export(db_session, settings)
    assert path.name == "nginx-mta-sts.conf"
    assert "server {" not in path.read_text(encoding="utf-8")
