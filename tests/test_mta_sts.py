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
        portal_domain="portal.example.com",
        sso_portal_default_realm_slug="default",
        exports_dir=str(tmp_path / "exports"),
        portal_data_dir=str(tmp_path / "data"),
        vault_portal_internal_token="test-secret",
    )  # type: ignore[call-arg]


def test_parse_mx_strips_url_junk():
    hosts = parse_mx_hosts("://mail.example.com\nhttps://mx2.example.com/path\n*.example.com")
    assert hosts == ["mail.example.com", "mx2.example.com", "*.example.com"]


def test_validate_mail_domain_rejects_mta_sts_prefix():
    with pytest.raises(ValueError):
        validate_mail_domain("mta-sts.example.com")
    assert validate_mail_domain("example.com") == "example.com"


def test_build_policy_text_rfc_shape():
    text = build_policy_text(
        mode="testing",
        mx_hosts=["mail.example.com", "*.example.com"],
        max_age=604800,
    )
    assert text == (
        "version: STSv1\n"
        "mode: testing\n"
        "mx: mail.example.com\n"
        "mx: *.example.com\n"
        "max_age: 604800\n"
    )


def test_generate_nginx_conf_serves_well_known():
    conf = generate_nginx_mta_sts_conf(
        enabled=True,
        mail_domain="example.com",
        mode="enforce",
        mx_hosts=["mail.example.com"],
        max_age=604800,
    )
    assert "server_name mta-sts.example.com;" in conf
    assert "listen 0.0.0.0:8080;" in conf
    assert "access_log /var/log/nginx/apps/mta-sts.access.log" in conf
    assert "[::]" not in conf
    assert "listen 8080;" not in conf  # bare port can still open AF_INET6
    assert "location = /.well-known/mta-sts.txt" in conf
    assert "mode: enforce" in conf
    assert "mx: mail.example.com" in conf


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
        mail_domain="example.com",
        mode="testing",
        mx_hosts="mail.example.com\n*.example.com",
        max_age=604800,
    )
    path = Path(settings.exports_dir) / "nginx-mta-sts.conf"
    assert path.is_file()
    body = path.read_text(encoding="utf-8")
    assert "mta-sts.example.com" in body
    assert "mode: testing" in body

    manifest = build_acme_domains_manifest(db_session, settings)
    fqdns = {d["fqdn"] for d in manifest["domains"]}
    assert "mta-sts.example.com" in fqdns
    families = {d["fqdn"]: d["family"] for d in manifest["domains"]}
    assert families["mta-sts.example.com"] == "mta_sts"

    known = collect_known_hostnames(db_session, settings)
    assert "mta-sts.example.com" in known


def test_write_export_when_disabled(db_session, tmp_path):
    settings = _settings(tmp_path)
    path = write_mta_sts_nginx_export(db_session, settings)
    assert path.name == "nginx-mta-sts.conf"
    assert "server {" not in path.read_text(encoding="utf-8")


def test_setup_steps_reflect_public_probe(db_session, tmp_path):
    import json

    from app.mail.mta_sts_service import mta_sts_public_status, save_mta_sts_probe

    settings = _settings(tmp_path)
    update_mta_sts_settings(
        db_session,
        settings,
        actor="admin@test",
        enabled=True,
        mail_domain="example.com",
        mode="testing",
        mx_hosts="mail.example.com",
        max_age=604800,
    )
    status = mta_sts_public_status(db_session, settings)
    by_id = {s["id"]: s for s in status["setup_steps"]}
    assert by_id["config"]["status"] == "done"
    assert by_id["dns_a"]["status"] == "current"
    assert status["status_badge"] == "warn"

    save_mta_sts_probe(
        settings,
        {
            "ok": True,
            "dns_a_ok": True,
            "dns_a_detail": "Public → 10.0.0.10",
            "dns_txt_ok": True,
            "dns_txt_detail": "Public → v=STSv1; id=abc",
            "http_ok": True,
            "http_detail": "HTTPS 200 via 10.0.0.10",
            "expected_dns_txt": status["dns_txt"],
            "fqdn": "mta-sts.example.com",
        },
    )
    fqdn = "mta-sts.example.com"
    cert_dir = Path(settings.portal_data_dir) / "certs" / fqdn
    cert_dir.mkdir(parents=True)
    (cert_dir / "fullchain.pem").write_text("CERT", encoding="utf-8")
    (Path(settings.exports_dir) / "acme-domains.json").write_text(
        json.dumps({"domains": [{"fqdn": fqdn, "slug": "mta-sts", "family": "mta_sts"}]}),
        encoding="utf-8",
    )
    status2 = mta_sts_public_status(db_session, settings)
    by_id2 = {s["id"]: s for s in status2["setup_steps"]}
    assert by_id2["dns_a"]["status"] == "done"
    assert by_id2["dns_txt"]["status"] == "done"
    assert by_id2["acme"]["status"] == "done"
    assert by_id2["verify"]["status"] == "done"
    assert status2["status_badge"] == "ok"
