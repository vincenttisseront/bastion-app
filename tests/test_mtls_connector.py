"""Self-managed mTLS CA, client provisioning, CRL, nginx export."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.acme.mtls_ca import (
    ca_cert_path,
    ca_crl_path,
    ca_info,
    ca_key_path,
    ensure_self_managed_ca,
    fingerprint_sha256,
    issue_client_certificate,
    load_ca_cert,
    nginx_mtls_include_body,
    write_mtls_nginx_export,
)
from app.acme.mtls_client_service import (
    STATUS_ACTIVE,
    STATUS_REVOKED,
    get_mtls_client,
    provision_mtls_client,
    revoke_mtls_client,
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


def test_ensure_self_managed_ca_creates_p256_and_crl(tmp_path):
    settings = _settings(tmp_path)
    path = ensure_self_managed_ca(settings)
    assert path == ca_cert_path(settings)
    assert ca_key_path(settings).is_file()
    assert ca_crl_path(settings).is_file()

    key = serialization.load_pem_private_key(
        ca_key_path(settings).read_bytes(), password=None
    )
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    cert = load_ca_cert(settings)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True
    assert bc.value.path_length == 0

    # Idempotent
    ensure_self_managed_ca(settings)
    info = ca_info(settings)
    assert info is not None
    assert info.fingerprint_sha256 == fingerprint_sha256(cert)


def test_ca_key_mode_is_owner_rw_only(tmp_path):
    import sys

    settings = _settings(tmp_path)
    ensure_self_managed_ca(settings)
    if sys.platform == "win32":
        # NTFS ACLs — chmod bits are not authoritative; file must exist.
        assert ca_key_path(settings).is_file()
        return
    mode = ca_key_path(settings).stat().st_mode & 0o777
    assert mode & 0o077 == 0  # owner-only (0600)


def test_issue_client_certificate_bundle(tmp_path):
    settings = _settings(tmp_path)
    ensure_self_managed_ca(settings)
    cert, cert_pem, key_pem, bundle = issue_client_certificate(
        settings, app_name="billing"
    )
    assert b"BEGIN CERTIFICATE" in cert_pem
    assert b"BEGIN PRIVATE KEY" in key_pem or b"BEGIN EC PRIVATE KEY" in key_pem
    assert (bundle / "client.crt").is_file()
    assert (bundle / "client.key").is_file()
    assert (bundle / "ca.crt").is_file()
    assert cert.subject.get_attributes_for_oid(
        x509.oid.NameOID.COMMON_NAME
    )[0].value == "billing.bastion.internal"
    client_key = serialization.load_pem_private_key(key_pem, password=None)
    assert isinstance(client_key, ec.EllipticCurvePrivateKey)


def test_provision_and_revoke_rebuilds_crl(db_session, tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    monkeypatch.setattr(
        "app.acme.mtls_ca.request_nginx_reload",
        lambda _s: (True, "mocked"),
    )
    monkeypatch.setattr(
        "app.acme.mtls_client_service.request_nginx_reload",
        lambda _s: (True, "mocked"),
    )

    row = provision_mtls_client(
        db_session,
        settings,
        app_name="billing",
        actor="admin@example.com",
    )
    assert row.status == STATUS_ACTIVE
    assert row.cn == "billing.bastion.internal"
    assert get_mtls_client(db_session, "billing") is not None

    crl_before = ca_crl_path(settings).read_bytes()
    revoked = revoke_mtls_client(
        db_session,
        settings,
        app_name="billing",
        actor="admin@example.com",
    )
    assert revoked.status == STATUS_REVOKED
    crl_after = ca_crl_path(settings).read_bytes()
    assert crl_after != crl_before

    crl = x509.load_pem_x509_crl(crl_after)
    serials = {r.serial_number for r in crl}
    assert int(row.serial_number, 16) in serials


def test_provision_rejects_duplicate_active(db_session, tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    monkeypatch.setattr(
        "app.acme.mtls_client_service.request_nginx_reload",
        lambda _s: (True, "ok"),
    )
    provision_mtls_client(
        db_session, settings, app_name="api", actor="admin@example.com"
    )
    with pytest.raises(ValueError, match="déjà active"):
        provision_mtls_client(
            db_session, settings, app_name="api", actor="admin@example.com"
        )


def test_nginx_mtls_export_snippet(tmp_path):
    settings = _settings(tmp_path)
    path = write_mtls_nginx_export(settings)
    text = path.read_text(encoding="utf-8")
    assert "ssl_verify_client on" in text
    assert "ssl/mtls/ca.crt" in text
    assert "ssl/mtls/ca.crl" in text
    body = nginx_mtls_include_body()
    assert "ssl_verify_depth 1" in body


def test_sync_exports_copies_mtls_include():
    root = Path(__file__).resolve().parents[1]
    script = (root / "docker/nginx/sync-exports-to-confd.sh").read_text(
        encoding="utf-8"
    )
    assert "mtls-apps-generated.conf" in script
    assert "mtls-apps-generated.conf" in script


def test_security_template_has_mtls_anchor():
    root = Path(__file__).resolve().parents[1]
    html = (root / "app/templates/admin/security.html").read_text(
        encoding="utf-8"
    )
    assert 'id="mtls"' in html
    assert "/admin/security/mtls/provision" in html
    assert "Révoquer" in html
