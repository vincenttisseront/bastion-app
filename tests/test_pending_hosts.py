"""Unknown-Host discovery + pending approval → public_proxy."""

from __future__ import annotations

from pathlib import Path

from app.bastion.nginx_known_hosts_export import (
    collect_known_hostnames,
    generate_known_hosts_map,
    normalize_hostname,
    write_known_hosts_map,
)
from app.bastion.pending_host_service import (
    approve_pending_host,
    record_unknown_host,
    reject_pending_host,
    suggest_slug,
)
from app.models import App, PendingHost
from app.sso_settings import Settings


def test_normalize_hostname():
    assert normalize_hostname("Teleport.Example.FR:443") == "teleport.example.fr"
    assert normalize_hostname("  ") is None
    assert normalize_hostname("127.0.0.1") == "127.0.0.1"
    assert normalize_hostname("::1") is None


def test_known_hosts_map_never_emits_ipv6_or_dollar(db_session, tmp_path):
    settings = Settings(
        portal_domain="portal.example.fr",
        sso_portal_default_realm_slug="ar-systems",
        exports_dir=str(tmp_path / "exports"),
        vault_portal_internal_token="test-secret",
    )  # type: ignore[call-arg]
    text = generate_known_hosts_map(db_session, settings)
    assert "::" not in text
    assert "$bastion" not in text
    assert "127.0.0.1 0;" in text
    assert "portal.example.fr 0;" in text


def test_suggest_slug():
    assert suggest_slug("teleport.ar-systems.fr") == "teleport"


def test_known_hosts_map_includes_portal_and_apps(db_session, tmp_path):
    settings = Settings(
        portal_domain="portal.example.fr",
        sso_portal_default_realm_slug="ar-systems",
        exports_dir=str(tmp_path / "exports"),
        vault_portal_internal_token="test-secret",
    )  # type: ignore[call-arg]
    db_session.add(
        App(
            slug="status",
            label="Status",
            upstream_url="http://10.0.0.1/",
            access_mode="public_proxy",
            public_fqdn="status.example.fr",
            enabled=True,
        )
    )
    db_session.add(
        App(
            slug="wiki",
            label="Wiki",
            upstream_url="http://10.0.0.2/",
            access_mode="sso_gate",
            public_fqdn="wiki.example.fr",
            enabled=True,
        )
    )
    db_session.commit()
    known = collect_known_hostnames(db_session, settings)
    assert "portal.example.fr" in known
    assert "127.0.0.1" in known
    assert "status.example.fr" in known
    assert "wiki.example.fr" not in known  # sso_gate has no nginx Host vhost
    text = generate_known_hosts_map(db_session, settings)
    assert "status.example.fr 0;" in text
    path = write_known_hosts_map(db_session, settings)
    assert path.is_file()


def test_record_and_approve_pending_host(db_session, tmp_path):
    settings = Settings(
        portal_domain="portal.example.fr",
        sso_portal_default_realm_slug="ar-systems",
        exports_dir=str(tmp_path / "exports"),
        vault_portal_internal_token="test-secret",
    )  # type: ignore[call-arg]
    row = record_unknown_host(
        db_session,
        hostname="teleport.example.fr",
        client_ip="10.1.2.3",
        user_agent="curl/8",
        uri="/web/",
    )
    assert row is not None
    assert row.status == "pending"
    assert row.hit_count == 1
    from app.models import AuditLog

    audit = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "access_denied_unknown_host")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.target == "teleport.example.fr"
    assert audit.ip_address == "10.1.2.3"
    assert (audit.details or {}).get("uri") == "/web/"

    row2 = record_unknown_host(db_session, hostname="Teleport.example.fr", uri="/")
    assert row2.id == row.id
    assert row2.hit_count == 2

    pending, app = approve_pending_host(
        db_session,
        settings,
        host_id=row.id,
        actor="admin@example.fr",
        upstream_url="https://172.24.0.50:443/",
        slug="teleport",
        label="Teleport",
    )
    assert pending.status == "approved"
    assert app.access_mode == "public_proxy"
    assert app.public_fqdn == "teleport.example.fr"
    map_path = Path(settings.exports_dir) / "nginx-known-hosts.map"
    assert "teleport.example.fr 0;" in map_path.read_text(encoding="utf-8")
    conf = Path(settings.exports_dir) / "nginx-public-proxy-apps.conf"
    assert "teleport.example.fr" in conf.read_text(encoding="utf-8")


def test_reject_keeps_counting(db_session):
    row = record_unknown_host(db_session, hostname="evil.example.fr")
    reject_pending_host(db_session, host_id=row.id, actor="admin@example.fr")
    again = record_unknown_host(db_session, hostname="evil.example.fr")
    assert again.status == "rejected"
    assert again.hit_count == 2


def test_internal_unknown_host_requires_token(client):
    r = client.get("/internal/unknown-host", headers={"Host": "teleport.example.fr"})
    assert r.status_code in (401, 403)


def test_internal_unknown_host_records(client, db_session):
    r = client.get(
        "/internal/unknown-host",
        headers={
            "Host": "teleport.example.fr",
            "X-Portal-Internal-Token": "test-secret",
            "X-Discovered-Host": "teleport.example.fr",
            "X-Original-URI": "/web/",
        },
    )
    assert r.status_code == 503
    assert "Hôte non enregistré" in r.text
    assert "Domaines découverts" in r.text
    assert "teleport.example.fr" in r.text
    assert "/admin/pending-hosts" in r.text
    assert r.headers.get("x-bastion-unknown-host") == "1"
    row = db_session.query(PendingHost).filter_by(hostname="teleport.example.fr").first()
    assert row is not None
    assert row.status == "pending"
    from app.models import AuditLog

    audit = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "access_denied_unknown_host")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert (audit.details or {}).get("uri") == "/web/"


def test_docker_portal_has_unknown_host_rewrite():
    from pathlib import Path

    text = (
        Path(__file__).resolve().parents[1]
        / "docker/nginx/templates/vhost_sso_portal.conf.template"
    ).read_text(encoding="utf-8")
    assert "$bastion_unknown_host" in text
    assert "location = /__bastion_unknown_host" in text
    assert "location = /internal/unknown-host" in text
    assert "proxy_intercept_errors off" in text


def test_compose_has_traefik_catchall_labels():
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    assert "bastion-catchall" in text
    assert "PathPrefix(`/`)" in text or 'PathPrefix(`/`)' in text
    assert "priority=1" in text


def test_traefik_catchall_file_is_priority_one():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    for rel in (
        "docker/traefik/bastion-catchall.example.yml",
        "ansible/roles/bastion_app_docker/files/bastion-catchall.yml",
    ):
        text = (root / rel).read_text(encoding="utf-8")
        assert "priority: 1" in text
        assert "bastion-nginx:8080" in text
        assert "PathPrefix(`/`)" in text
