"""Hybrid ACME: CertificateDomain, HTTP-01 native client, nginx bridge, renew."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.acme.certificate_domain_service import (
    PROVIDER_DNS,
    PROVIDER_HTTP,
    STATUS_VALID,
    domains_needing_attention,
    get_certificate_domain,
    set_provider_type,
    sync_certificate_domains_from_manifest,
)
from app.acme.native_client import (
    AcmeNativeClient,
    AcmeNativeError,
    clear_http01_token,
    install_domain_cert,
    write_http01_token,
)
from app.acme.renew_service import renew_domain
from app.acme.settings_service import ensure_acme_settings
from app.bastion.acme_domains_export import (
    build_acme_domains_manifest,
    write_acme_domains_export,
)
from app.models import App
from app.sso_settings import Settings


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        portal_domain="portal.example.com",
        sso_portal_default_realm_slug="default",
        exports_dir=str(tmp_path / "exports"),
        portal_data_dir=str(tmp_path / "data"),
        acme_challenge_webroot=str(tmp_path / "acme-challenge"),
        vault_portal_internal_token="test-secret",
    )  # type: ignore[call-arg]


def _self_signed_pem(fqdn: str, *, days: int = 90) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, fqdn)]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(fqdn)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def test_sync_certificate_domains_defaults_http_without_cf(db_session, tmp_path):
    settings = _settings(tmp_path)
    ensure_acme_settings(db_session)
    rows = sync_certificate_domains_from_manifest(db_session, settings)
    assert any(r.domain == "portal.example.com" for r in rows)
    row = get_certificate_domain(db_session, "portal.example.com")
    assert row is not None
    assert row.provider_type == PROVIDER_HTTP


def test_set_provider_and_manifest_enrichment(db_session, tmp_path):
    settings = _settings(tmp_path)
    ensure_acme_settings(db_session)
    sync_certificate_domains_from_manifest(db_session, settings)
    set_provider_type(db_session, "portal.example.com", PROVIDER_DNS)
    path = write_acme_domains_export(db_session, settings)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["challenge"] == "hybrid"
    portal = next(d for d in data["domains"] if d["fqdn"] == "portal.example.com")
    assert portal["provider"] == PROVIDER_DNS
    assert portal["challenge"] == "dns-01"


def test_sidecar_reconcile_script_skips_http_native():
    root = Path(__file__).resolve().parents[1]
    script = (root / "docker/acme/reconcile-certs.sh").read_text(encoding="utf-8")
    assert "http_native" in script
    assert "http-01" in script


def test_sync_acme_tls_serves_challenge_before_redirect():
    root = Path(__file__).resolve().parents[1]
    script = (root / "docker/nginx/sync-acme-tls.sh").read_text(encoding="utf-8")
    assert "acme-challenge" in script
    challenge_idx = script.index("acme-challenge")
    redirect_idx = script.index("return 301")
    assert challenge_idx < redirect_idx
    include = root / "docker/nginx/includes/acme-challenge.conf"
    assert include.is_file()
    assert ".well-known/acme-challenge" in include.read_text(encoding="utf-8")


def test_http01_token_write_and_clear(tmp_path):
    webroot = tmp_path / "acme-challenge"
    path = write_http01_token(webroot, "tok123", "tok123.thumb")
    assert path.is_file()
    assert path.read_text(encoding="utf-8") == "tok123.thumb"
    assert path == webroot / ".well-known" / "acme-challenge" / "tok123"
    clear_http01_token(webroot, "tok123")
    assert not path.exists()


def test_http01_token_rejects_path_traversal(tmp_path):
    with pytest.raises(AcmeNativeError):
        write_http01_token(tmp_path, "../evil", "x")


def test_install_domain_cert_sidecar_layout(tmp_path):
    settings = _settings(tmp_path)
    fullchain, privkey = _self_signed_pem("app.example.com")
    dest = install_domain_cert(
        settings,
        "app.example.com",
        fullchain_pem=fullchain,
        privkey_pem=privkey,
    )
    assert (dest / "fullchain.pem").is_file()
    assert (dest / "privkey.pem").is_file()
    assert (Path(settings.portal_data_dir) / "certs" / ".reload_nginx").is_file()


def test_domains_needing_attention_renew_soon(db_session, tmp_path):
    settings = _settings(tmp_path)
    ensure_acme_settings(db_session)
    sync_certificate_domains_from_manifest(db_session, settings)
    row = get_certificate_domain(db_session, "portal.example.com")
    assert row is not None
    fullchain, privkey = _self_signed_pem("portal.example.com", days=10)
    install_domain_cert(
        settings,
        "portal.example.com",
        fullchain_pem=fullchain,
        privkey_pem=privkey,
    )
    sync_certificate_domains_from_manifest(db_session, settings)
    row = get_certificate_domain(db_session, "portal.example.com")
    assert row is not None
    assert row.status == STATUS_VALID
    due = domains_needing_attention(db_session)
    assert any(r.domain == "portal.example.com" for r in due)


class _FakeTransport(httpx.BaseTransport):
    """Minimal ACME directory → order → authz → finalize → cert sequence."""

    def __init__(self, fqdn: str, fullchain: bytes):
        self.fqdn = fqdn
        self.fullchain = fullchain
        self.nonce = 0
        self.order_status = "pending"
        self.authz_status = "pending"
        self.chall_triggered = False

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.nonce += 1
        headers = {"Replay-Nonce": f"nonce-{self.nonce}"}
        url = str(request.url)

        if url.endswith("/directory"):
            return httpx.Response(
                200,
                headers=headers,
                json={
                    "newNonce": "https://acme.test/new-nonce",
                    "newAccount": "https://acme.test/new-account",
                    "newOrder": "https://acme.test/new-order",
                },
            )
        if url.endswith("/new-nonce"):
            return httpx.Response(200, headers=headers)
        if url.endswith("/new-account"):
            headers["Location"] = "https://acme.test/acct/1"
            return httpx.Response(201, headers=headers, json={"status": "valid"})
        if url.endswith("/new-order"):
            headers["Location"] = "https://acme.test/order/1"
            self.order_status = "pending"
            self.authz_status = "pending"
            return httpx.Response(
                201,
                headers=headers,
                json={
                    "status": "pending",
                    "authorizations": ["https://acme.test/authz/1"],
                    "finalize": "https://acme.test/order/1/finalize",
                },
            )
        if url.endswith("/authz/1"):
            if self.chall_triggered:
                self.authz_status = "valid"
                self.order_status = "ready"
            return httpx.Response(
                200,
                headers=headers,
                json={
                    "status": self.authz_status,
                    "challenges": [
                        {
                            "type": "http-01",
                            "url": "https://acme.test/chall/1",
                            "token": "test-token",
                        }
                    ],
                },
            )
        if url.endswith("/chall/1"):
            self.chall_triggered = True
            return httpx.Response(
                200, headers=headers, json={"status": "processing"}
            )
        if url.endswith("/order/1/finalize"):
            self.order_status = "valid"
            return httpx.Response(
                200,
                headers=headers,
                json={
                    "status": "valid",
                    "certificate": "https://acme.test/cert/1",
                },
            )
        if url.endswith("/order/1"):
            body = {
                "status": self.order_status,
                "authorizations": ["https://acme.test/authz/1"],
                "finalize": "https://acme.test/order/1/finalize",
            }
            if self.order_status == "valid":
                body["certificate"] = "https://acme.test/cert/1"
            return httpx.Response(200, headers=headers, json=body)
        if url.endswith("/cert/1"):
            return httpx.Response(
                200, headers=headers, content=self.fullchain
            )
        return httpx.Response(404, headers=headers, text="missing " + url)


def test_native_client_issue_or_renew_mocked(db_session, tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    ensure_acme_settings(db_session)
    fullchain, _ = _self_signed_pem("portal.example.com", days=60)
    transport = _FakeTransport("portal.example.com", fullchain)
    client = httpx.Client(transport=transport)

    # Speed up poll sleeps in client
    monkeypatch.setattr("app.acme.native_client.time.sleep", lambda *_: None)

    with AcmeNativeClient(
        settings,
        acme_ca="letsencrypt_test",
        http_client=client,
        directory_url="https://acme.test/directory",
    ) as acme:
        dest = acme.issue_or_renew("portal.example.com")

    assert (dest / "fullchain.pem").is_file()
    assert (dest / "privkey.pem").is_file()
    # Challenge cleaned up
    token_path = (
        Path(settings.acme_challenge_webroot)
        / ".well-known"
        / "acme-challenge"
        / "test-token"
    )
    assert not token_path.exists()


def test_renew_domain_http_native_dispatch(db_session, tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    row = ensure_acme_settings(db_session)
    row.enabled = True
    row.acme_ca = "letsencrypt_test"
    db_session.commit()
    sync_certificate_domains_from_manifest(db_session, settings)
    set_provider_type(db_session, "portal.example.com", PROVIDER_HTTP)

    called: dict[str, str] = {}

    def fake_issue(settings_arg, fqdn, **kwargs):
        called["fqdn"] = fqdn
        fullchain, privkey = _self_signed_pem(fqdn, days=60)
        return install_domain_cert(
            settings_arg, fqdn, fullchain_pem=fullchain, privkey_pem=privkey
        )

    monkeypatch.setattr(
        "app.acme.renew_service.issue_or_renew_http01", fake_issue
    )
    ok, msg = renew_domain(
        db_session, settings, "portal.example.com", actor="admin@example.com"
    )
    assert ok is True
    assert called["fqdn"] == "portal.example.com"
    row = get_certificate_domain(db_session, "portal.example.com")
    assert row is not None
    assert row.status == STATUS_VALID


def test_build_manifest_still_lists_apps(db_session, tmp_path):
    settings = _settings(tmp_path)
    db_session.add(
        App(
            slug="status",
            label="Status",
            upstream_url="http://10.0.0.2/",
            access_mode="public_proxy",
            public_fqdn="status.example.com",
            enabled=True,
        )
    )
    db_session.commit()
    manifest = build_acme_domains_manifest(db_session, settings)
    fqdns = {d["fqdn"] for d in manifest["domains"]}
    assert "portal.example.com" in fqdns
    assert "status.example.com" in fqdns

