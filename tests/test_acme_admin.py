"""Admin ACME settings + domain status."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.acme.settings_service import (
    build_acme_live_status,
    ensure_acme_settings,
    get_acme_config,
    list_domain_statuses,
    read_acme_reconcile_log,
    sync_reconcile_from_sidecar,
    update_acme_settings,
    write_acme_runtime_env,
)
from app.models import App
from app.sso_settings import Settings, get_settings


def _settings(tmp_path: Path) -> Settings:
    get_settings.cache_clear()
    return Settings(
        portal_domain="portal.example.fr",
        sso_portal_default_realm_slug="ar-systems",
        exports_dir=str(tmp_path / "exports"),
        portal_data_dir=str(tmp_path / "data"),
        vault_portal_internal_token="test-secret",
    )  # type: ignore[call-arg]


def _write_self_signed(cert_dir: Path, fqdn: str, days: int = 90) -> None:
    cert_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    (cert_dir / "fullchain.pem").write_bytes(cert.public_bytes(Encoding.PEM))
    (cert_dir / "privkey.pem").write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    )


def test_ensure_and_update_acme_settings(db_session, tmp_path):
    settings = _settings(tmp_path)
    row = ensure_acme_settings(db_session)
    assert row.id == 1
    assert row.enabled is False

    update_acme_settings(
        db_session,
        settings,
        enabled=True,
        dns_api="dns_cf",
        acme_ca="letsencrypt_test",
        cf_account_id="acc",
        cf_zone_id="zone",
        cf_token="cf-secret-token",
        clear_cf_token=False,
        actor="admin@example.fr",
    )
    cfg = get_acme_config(db_session)
    assert cfg.enabled is True
    assert cfg.acme_ca == "letsencrypt_test"
    assert cfg.cf_token_configured is True
    assert cfg.cf_zone_id == "zone"

    env_path = Path(settings.exports_dir) / "acme-runtime.env"
    assert env_path.is_file()
    text = env_path.read_text(encoding="utf-8")
    assert "ACME_ENABLED=1" in text
    assert "CF_Token=" in text
    assert "cf-secret-token" in text
    assert "ACME_ACCOUNT_EMAIL=acme@portal.example.fr" in text
    assert "PORTAL_DOMAIN=portal.example.fr" in text


def test_list_domain_statuses_reads_certs(db_session, tmp_path):
    settings = _settings(tmp_path)
    db_session.add(
        App(
            slug="teleport",
            label="Teleport",
            upstream_url="https://10.0.0.1/",
            access_mode="public_proxy",
            public_fqdn="teleport.example.fr",
            enabled=True,
        )
    )
    db_session.commit()

    missing = list_domain_statuses(db_session, settings)
    teleport = next(d for d in missing if d.fqdn == "teleport.example.fr")
    assert teleport.status == "missing"

    _write_self_signed(Path(settings.portal_data_dir) / "certs" / "teleport.example.fr", "teleport.example.fr")
    statuses = list_domain_statuses(db_session, settings)
    teleport = next(d for d in statuses if d.fqdn == "teleport.example.fr")
    assert teleport.has_cert is True
    assert teleport.status == "placeholder"  # self-signed
    assert teleport.days_left is not None


def test_admin_acme_page(client, db_session):
    resp = client.get(
        "/admin/acme",
        headers={"X-Email": "admin@example.com", "X-Groups": "portal-admins"},
    )
    assert resp.status_code == 200
    assert "Let's Encrypt" in resp.text
    assert "bastion" in resp.text.lower() or "FQDN" in resp.text
    assert 'action="/admin/acme/settings"' in resp.text
    assert 'action="/admin/acme/reconcile"' in resp.text
    assert "/api/admin/acme/status" in resp.text
    assert "pas de record manuel" in resp.text.lower() or "DNS-01" in resp.text


def test_acme_live_status_reads_log(db_session, tmp_path):
    settings = _settings(tmp_path)
    certs = Path(settings.portal_data_dir) / "certs"
    certs.mkdir(parents=True)
    (certs / "acme-reconcile.log").write_text(
        "[2026-07-28T10:00:00Z] ISSUE portal.example.fr via DNS-01\n",
        encoding="utf-8",
    )
    (certs / "acme-last-run.json").write_text(
        '{"finished_at":"2026-07-28T10:00:05Z","status":"ok","message":"Reconcile OK","ok":1,"failed":0}',
        encoding="utf-8",
    )
    ensure_acme_settings(db_session)
    row = ensure_acme_settings(db_session)
    row.last_reconcile_status = "pending"
    row.last_reconcile_message = "waiting"
    db_session.commit()

    log = read_acme_reconcile_log(settings)
    assert log["exists"] is True
    assert "ISSUE portal.example.fr" in log["text"]

    assert sync_reconcile_from_sidecar(db_session, settings) is True
    cfg = get_acme_config(db_session)
    assert cfg.last_reconcile_status == "ok"

    payload = build_acme_live_status(db_session, settings)
    assert payload["log"]["exists"] is True
    assert "DNS-01" in payload["dns01_hint"]
    assert payload["last_run"]["status"] == "ok"


def test_admin_acme_status_api(client, db_session):
    resp = client.get(
        "/api/admin/acme/status",
        headers={"X-Email": "admin@example.com", "X-Groups": "portal-admins"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "domains" in data
    assert "log" in data
    assert "dns01_hint" in data


def test_write_acme_runtime_env_disabled_omits_token(db_session, tmp_path):
    settings = _settings(tmp_path)
    update_acme_settings(
        db_session,
        settings,
        enabled=False,
        dns_api="dns_cf",
        acme_ca="letsencrypt",
        cf_account_id="",
        cf_zone_id="",
        cf_token="should-not-export",
        clear_cf_token=False,
        actor="admin@example.fr",
    )
    path = write_acme_runtime_env(db_session, settings)
    text = path.read_text(encoding="utf-8")
    assert "ACME_ENABLED=0" in text
    assert "should-not-export" not in text
