"""Self-managed internal mTLS CA (ECDSA P-256, PKCS#8 0600 on certs volume).

Artifacts live under ``{certs_dir}/mtls/`` (portal) ≡ ``/etc/nginx/ssl/mtls/`` (nginx).
Never log private key material.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.acme.settings_service import certs_dir
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

_CA_LOCK = threading.Lock()

CA_VALIDITY_DAYS = 3650  # 10 years
CLIENT_VALIDITY_DAYS = 365
CRL_NEXT_UPDATE_DAYS = 30
INTERNAL_CN_SUFFIX = ".bastion.internal"
CA_COMMON_NAME = "Bastion Internal Self-Managed CA"
CA_ORG_NAME = "Bastion Network"

NGINX_MTLS_DIR = "/etc/nginx/ssl/mtls"


class MtlsCaError(RuntimeError):
    """mTLS CA / client certificate failure (message must not contain secrets)."""


@dataclass(frozen=True)
class MtlsCaInfo:
    subject: str
    fingerprint_sha256: str
    not_before: datetime
    not_after: datetime
    serial_hex: str
    path: str


def mtls_dir(settings: Settings) -> Path:
    return certs_dir(settings) / "mtls"


def clients_dir(settings: Settings) -> Path:
    return mtls_dir(settings) / "clients"


def ca_key_path(settings: Settings) -> Path:
    return mtls_dir(settings) / "ca.key"


def ca_cert_path(settings: Settings) -> Path:
    return mtls_dir(settings) / "ca.crt"


def ca_crl_path(settings: Settings) -> Path:
    return mtls_dir(settings) / "ca.crl"


def _atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}.{threading.get_ident()}")
    try:
        tmp.write_bytes(data)
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    finally:
        if tmp.is_file():
            try:
                tmp.unlink()
            except OSError:
                pass


def _ca_subject() -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORG_NAME),
        ]
    )


def _load_ca_key(settings: Settings) -> ec.EllipticCurvePrivateKey:
    path = ca_key_path(settings)
    if not path.is_file():
        raise MtlsCaError("mTLS CA key missing — call ensure_self_managed_ca first")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise MtlsCaError("mTLS CA key must be ECDSA P-256")
    return key


def load_ca_cert(settings: Settings) -> x509.Certificate:
    path = ca_cert_path(settings)
    if not path.is_file():
        raise MtlsCaError("mTLS CA certificate missing")
    return x509.load_pem_x509_certificate(path.read_bytes())


def fingerprint_sha256(cert: x509.Certificate) -> str:
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def ca_info(settings: Settings) -> MtlsCaInfo | None:
    path = ca_cert_path(settings)
    if not path.is_file():
        return None
    try:
        cert = load_ca_cert(settings)
    except MtlsCaError:
        return None
    not_before = (
        cert.not_valid_before_utc
        if hasattr(cert, "not_valid_before_utc")
        else cert.not_valid_before.replace(tzinfo=timezone.utc)
    )
    not_after = (
        cert.not_valid_after_utc
        if hasattr(cert, "not_valid_after_utc")
        else cert.not_valid_after.replace(tzinfo=timezone.utc)
    )
    return MtlsCaInfo(
        subject=cert.subject.rfc4514_string(),
        fingerprint_sha256=fingerprint_sha256(cert),
        not_before=not_before,
        not_after=not_after,
        serial_hex=f"{cert.serial_number:x}",
        path=str(path),
    )


def _build_empty_crl(
    issuer: x509.Name,
    private_key: ec.EllipticCurvePrivateKey,
    *,
    now: datetime,
    revoked: Iterable[tuple[int, datetime]] = (),
) -> x509.CertificateRevocationList:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer)
        .last_update(now)
        .next_update(now + timedelta(days=CRL_NEXT_UPDATE_DAYS))
    )
    for serial, revoked_at in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(revoked_at)
            .build()
        )
    return builder.sign(private_key, hashes.SHA256())


def write_crl(
    settings: Settings,
    *,
    revoked: Iterable[tuple[int, datetime]] = (),
) -> Path:
    """Rebuild ``ca.crl`` (empty or with revoked serials)."""
    private_key = _load_ca_key(settings)
    cert = load_ca_cert(settings)
    now = datetime.now(timezone.utc)
    crl = _build_empty_crl(
        cert.subject, private_key, now=now, revoked=revoked
    )
    path = ca_crl_path(settings)
    _atomic_write_bytes(
        path, crl.public_bytes(serialization.Encoding.PEM), mode=0o644
    )
    return path


def ensure_self_managed_ca(settings: Settings) -> Path:
    """Create CA key/cert + empty CRL if missing. Idempotent."""
    key_path = ca_key_path(settings)
    cert_path = ca_cert_path(settings)
    crl_path = ca_crl_path(settings)

    with _CA_LOCK:
        mtls_dir(settings).mkdir(parents=True, exist_ok=True)
        clients_dir(settings).mkdir(parents=True, exist_ok=True)

        if key_path.is_file() and cert_path.is_file():
            if not crl_path.is_file():
                write_crl(settings, revoked=())
            return cert_path

        now = datetime.now(timezone.utc)
        private_key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = _ca_subject()
        ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=CA_VALIDITY_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(ski, critical=False)
            .sign(private_key, hashes.SHA256())
        )

        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        _atomic_write_bytes(key_path, key_pem, mode=0o600)
        _atomic_write_bytes(
            cert_path,
            cert.public_bytes(serialization.Encoding.PEM),
            mode=0o644,
        )
        crl = _build_empty_crl(subject, private_key, now=now, revoked=())
        _atomic_write_bytes(
            crl_path, crl.public_bytes(serialization.Encoding.PEM), mode=0o644
        )
        logger.info(
            "mtls.ca: self-managed CA created fingerprint=%s",
            fingerprint_sha256(cert),
        )
        return cert_path


def client_cn_for_app(app_name: str) -> str:
    slug = (app_name or "").strip().lower()
    return f"{slug}{INTERNAL_CN_SUFFIX}"


def issue_client_certificate(
    settings: Settings,
    *,
    app_name: str,
    validity_days: int = CLIENT_VALIDITY_DAYS,
) -> tuple[x509.Certificate, bytes, bytes, Path]:
    """Issue EC P-256 client cert signed by the internal CA.

    Returns ``(cert, cert_pem, key_pem, bundle_dir)``.
    """
    ensure_self_managed_ca(settings)
    slug = (app_name or "").strip().lower()
    if not slug or "/" in slug or ".." in slug or "\\" in slug:
        raise MtlsCaError("invalid mTLS app_name")
    cn = client_cn_for_app(slug)
    ca_key = _load_ca_key(settings)
    ca_cert = load_ca_cert(settings)
    now = datetime.now(timezone.utc)
    client_key = ec.generate_private_key(ec.SECP256R1())
    serial = x509.random_serial_number()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORG_NAME),
        ]
    )
    ski = x509.SubjectKeyIdentifier.from_public_key(client_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False,
        )
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    bundle = clients_dir(settings) / slug
    _atomic_write_bytes(bundle / "client.crt", cert_pem, mode=0o644)
    _atomic_write_bytes(bundle / "client.key", key_pem, mode=0o600)
    _atomic_write_bytes(bundle / "ca.crt", ca_pem, mode=0o644)
    logger.info("mtls.ca: issued client cert cn=%s serial=%x", cn, serial)
    return cert, cert_pem, key_pem, bundle


def nginx_mtls_include_body() -> str:
    """Snippet included by internal SSL server blocks requiring client certs."""
    return (
        "# Generated by bastion-app mTLS connector — do not edit\n"
        f"ssl_client_certificate {NGINX_MTLS_DIR}/ca.crt;\n"
        f"ssl_crl {NGINX_MTLS_DIR}/ca.crl;\n"
        "ssl_verify_client on;\n"
        "ssl_verify_depth 1;\n"
    )


def write_mtls_nginx_export(settings: Settings) -> Path:
    """Write exports/mtls-apps-generated.conf for sync-exports-to-confd."""
    ensure_self_managed_ca(settings)
    exports = Path(settings.exports_dir)
    exports.mkdir(parents=True, exist_ok=True)
    path = exports / "mtls-apps-generated.conf"
    _atomic_write_bytes(
        path, nginx_mtls_include_body().encode("utf-8"), mode=0o644
    )
    return path


def request_nginx_reload(settings: Settings) -> tuple[bool, str]:
    """Nudge nginx watcher + optional docker smoke reload (Phase D/E pattern)."""
    try:
        (certs_dir(settings) / ".reload_nginx").write_text(
            datetime.now(timezone.utc).isoformat(), encoding="utf-8"
        )
    except OSError as exc:
        logger.warning("mtls: could not touch .reload_nginx: %s", exc)

    try:
        from app.bastion.waf_reactivation import sync_and_reload

        return sync_and_reload(settings)
    except Exception as exc:
        logger.warning("mtls: sync_and_reload unavailable: %s", exc)
        return True, "reload signalled via .reload_nginx (watcher)"
