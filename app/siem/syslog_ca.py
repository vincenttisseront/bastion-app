"""Syslog TLS collector CA — validation, atomic store, status (no PEM in logs)."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import socket
import ssl
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

from app.sso_settings import Settings, get_settings

logger = logging.getLogger(__name__)

DEFAULT_RELATIVE_PATH = "certs/siem/syslog-collector-ca.pem"
ACTIVE_BASENAME = "syslog-collector-ca.pem"
STAGING_BASENAME = "syslog-collector-ca.pem.staging"
BACKUP_BASENAME = "syslog-collector-ca.pem.bak"
LOCK_BASENAME = "syslog-collector-ca.lock"
MAX_CA_BYTES = 64 * 1024

_PRIVATE_KEY_MARKERS = (
    b"BEGIN PRIVATE KEY",
    b"BEGIN RSA PRIVATE KEY",
    b"BEGIN EC PRIVATE KEY",
    b"BEGIN ENCRYPTED PRIVATE KEY",
    b"BEGIN OPENSSH PRIVATE KEY",
)

_SAFE_LOGICAL_NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

# Process-local lock (complements file lock for same-process races).
_PROCESS_LOCK = threading.RLock()


class SyslogCaError(ValueError):
    """Validation or store failure — message must never include PEM bytes."""


@dataclass(frozen=True)
class CaCertificateInfo:
    subject: str
    issuer: str
    serial_number: str
    fingerprint_sha256: str
    not_before: datetime
    not_after: datetime
    basic_constraints_ca: bool
    key_usage: list[str]
    subject_key_identifier: str | None
    authority_key_identifier: str | None
    pem_bytes: bytes

    def public_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "fingerprint_sha256": self.fingerprint_sha256,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "basic_constraints_ca": self.basic_constraints_ca,
            "key_usage": list(self.key_usage),
            "subject_key_identifier": self.subject_key_identifier,
            "authority_key_identifier": self.authority_key_identifier,
        }


def sanitize_logical_name(filename: str | None) -> str:
    raw = (filename or "").strip().replace("\\", "/").split("/")[-1]
    if not raw or not _SAFE_LOGICAL_NAME.match(raw):
        return ACTIVE_BASENAME
    lower = raw.lower()
    if not (lower.endswith(".pem") or lower.endswith(".crt")):
        return ACTIVE_BASENAME
    return raw


def portal_data_root(settings: Settings | None = None) -> Path:
    settings = settings or get_settings()
    return Path(settings.portal_data_dir).resolve()


def normalize_relative_path(relative: str | None) -> str:
    rel = (relative or DEFAULT_RELATIVE_PATH).strip().replace("\\", "/")
    if not rel or rel.startswith("/") or ".." in rel.split("/"):
        raise SyslogCaError("chemin CA relatif invalide")
    if not rel.endswith(".pem"):
        raise SyslogCaError("chemin CA relatif invalide")
    return rel


def resolve_ca_path(
    settings: Settings | None = None,
    *,
    relative_path: str | None = None,
) -> Path:
    """Absolute path visible to the Bastion process (container path under Docker)."""
    rel = normalize_relative_path(relative_path)
    root = portal_data_root(settings)
    full = (root / rel).resolve()
    try:
        full.relative_to(root)
    except ValueError as exc:
        raise SyslogCaError("chemin CA hors de PORTAL_DATA_DIR") from exc
    if full.name != ACTIVE_BASENAME:
        raise SyslogCaError("seul le fichier CA actif est autorisé")
    return full


def ca_dir_for(active_path: Path) -> Path:
    return active_path.parent


def staging_path_for(active_path: Path) -> Path:
    return active_path.parent / STAGING_BASENAME


def backup_path_for(active_path: Path) -> Path:
    return active_path.parent / BACKUP_BASENAME


def lock_path_for(active_path: Path) -> Path:
    return active_path.parent / LOCK_BASENAME


def _fingerprint_sha256(cert: x509.Certificate) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding

    digest = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2)).upper()


def _ext_key_usage(cert: x509.Certificate) -> list[str]:
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return []
    names: list[str] = []
    for attr in (
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
    ):
        try:
            if getattr(ku, attr):
                names.append(attr)
        except ValueError:
            continue
    return names


def _ski(cert: x509.Certificate) -> str | None:
    try:
        ski = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value
        return ski.digest.hex()
    except x509.ExtensionNotFound:
        return None


def _aki(cert: x509.Certificate) -> str | None:
    try:
        aki = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        ).value
        if aki.key_identifier:
            return aki.key_identifier.hex()
    except x509.ExtensionNotFound:
        return None
    return None


def parse_and_validate_ca_pem(data: bytes) -> CaCertificateInfo:
    """Validate uploaded bytes; never log or return raw PEM in error messages."""
    if not data:
        raise SyslogCaError("fichier CA vide")
    if len(data) > MAX_CA_BYTES:
        raise SyslogCaError("fichier CA trop volumineux")
    if any(marker in data for marker in _PRIVATE_KEY_MARKERS):
        raise SyslogCaError("clé privée refusée — importez uniquement un certificat CA public")
    text = data.lstrip()
    if b"BEGIN CERTIFICATE" not in text:
        raise SyslogCaError("contenu non PEM (certificat X.509 attendu)")
    # Reject PEM bundles that also embed a key (already covered) or multiple certs for v1.
    begin_count = text.count(b"BEGIN CERTIFICATE")
    if begin_count != 1:
        raise SyslogCaError("un seul certificat CA PEM est accepté")

    try:
        cert = x509.load_pem_x509_certificate(data, default_backend())
    except Exception as exc:
        raise SyslogCaError("certificat X.509 invalide") from exc

    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound as exc:
        raise SyslogCaError("Basic Constraints manquant (CA:TRUE requis)") from exc
    if not bc.ca:
        raise SyslogCaError("certificat non-CA (Basic Constraints CA:TRUE requis)")

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
    now = datetime.now(timezone.utc)
    if not_after <= now:
        raise SyslogCaError("certificat CA expiré")
    if not_before > now:
        raise SyslogCaError("certificat CA pas encore valide")

    from cryptography.hazmat.primitives.serialization import Encoding

    pem_out = cert.public_bytes(Encoding.PEM)
    return CaCertificateInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=format(cert.serial_number, "x"),
        fingerprint_sha256=_fingerprint_sha256(cert),
        not_before=not_before,
        not_after=not_after,
        basic_constraints_ca=True,
        key_usage=_ext_key_usage(cert),
        subject_key_identifier=_ski(cert),
        authority_key_identifier=_aki(cert),
        pem_bytes=pem_out,
    )


def read_ca_file_info(path: Path) -> CaCertificateInfo:
    if not path.is_file():
        raise SyslogCaError("fichier CA absent")
    # Never read staging as active.
    if path.name != ACTIVE_BASENAME:
        raise SyslogCaError("lecture réservée au fichier CA actif")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise SyslogCaError("lecture du fichier CA refusée") from exc
    return parse_and_validate_ca_pem(data)


def is_active_ca_valid(
    settings: Settings | None = None,
    *,
    relative_path: str | None = None,
) -> bool:
    try:
        path = resolve_ca_path(settings, relative_path=relative_path)
        read_ca_file_info(path)
        return True
    except SyslogCaError:
        return False


def derive_ca_status(
    settings: Settings | None = None,
    *,
    relative_path: str | None = None,
    tls_test_ok: bool | None = None,
) -> dict[str, Any]:
    """Status derived from the active file — never from a stale DB flag alone."""
    rel = None
    try:
        rel = normalize_relative_path(relative_path or DEFAULT_RELATIVE_PATH)
        path = resolve_ca_path(settings, relative_path=rel)
    except SyslogCaError:
        return {
            "configured": False,
            "valid": False,
            "badge": "missing",
            "relative_path": None,
            "tls_verify": True,
        }

    if not path.is_file():
        return {
            "configured": False,
            "valid": False,
            "badge": "missing",
            "relative_path": rel,
            "tls_verify": True,
        }

    try:
        info = read_ca_file_info(path)
    except SyslogCaError as exc:
        msg = str(exc)
        badge = "expired" if "expiré" in msg else "invalid"
        return {
            "configured": True,
            "valid": False,
            "badge": badge,
            "relative_path": rel,
            "error": msg,
            "tls_verify": True,
        }

    badge = "valid"
    if tls_test_ok is False:
        badge = "test_required"
    elif tls_test_ok is None:
        badge = "configured"

    return {
        "configured": True,
        "valid": True,
        "badge": badge,
        "relative_path": rel,
        "tls_verify": True,
        **info.public_dict(),
    }


@contextmanager
def _file_lock(lock_file: Path) -> Iterator[None]:
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_file, "a+b")
    try:
        if os.name == "nt":
            import msvcrt

            fh.seek(0)
            if fh.read(1) == b"":
                fh.write(b"\0")
                fh.flush()
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            logger.debug("syslog CA lock release failed", exc_info=True)
        fh.close()


def _set_file_mode(path: Path) -> None:
    """Restrictive mode when the OS supports it; no chown, no recursive chmod."""
    try:
        os.chmod(path, 0o644)
    except OSError:
        logger.debug("syslog CA chmod skipped for %s", path.name)


def write_staging_ca(active_path: Path, pem_bytes: bytes) -> Path:
    staging = staging_path_for(active_path)
    active_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = staging.with_suffix(staging.suffix + ".tmp")
    tmp.write_bytes(pem_bytes)
    _set_file_mode(tmp)
    # Ensure Bastion process can read staging before probe.
    try:
        _ = tmp.read_bytes()
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        raise SyslogCaError("fichier CA temporaire illisible") from exc
    os.replace(tmp, staging)
    _set_file_mode(staging)
    return staging


def commit_staging_to_active(
    active_path: Path,
    *,
    expected_fingerprint: str,
) -> None:
    """Backup active → replace with staging → verify fingerprint. Never leave staging as active."""
    staging = staging_path_for(active_path)
    backup = backup_path_for(active_path)
    if not staging.is_file():
        raise SyslogCaError("fichier staging absent")

    with _PROCESS_LOCK:
        with _file_lock(lock_path_for(active_path)):
            if active_path.is_file():
                os.replace(active_path, backup)
            os.replace(staging, active_path)
            _set_file_mode(active_path)
            try:
                info = read_ca_file_info(active_path)
            except SyslogCaError:
                _restore_backup(active_path, backup)
                raise
            if info.fingerprint_sha256 != expected_fingerprint:
                _restore_backup(active_path, backup)
                raise SyslogCaError("empreinte CA active incohérente après commit")


def _restore_backup(active_path: Path, backup: Path) -> None:
    if backup.is_file():
        os.replace(backup, active_path)
        _set_file_mode(active_path)
    elif active_path.is_file():
        # Broken active without backup — remove to avoid unverified CA.
        active_path.unlink(missing_ok=True)


def rollback_active_from_backup(active_path: Path) -> bool:
    """Restore previous active CA from .bak. Returns True if restored."""
    backup = backup_path_for(active_path)
    with _PROCESS_LOCK:
        with _file_lock(lock_path_for(active_path)):
            if not backup.is_file():
                return False
            os.replace(backup, active_path)
            _set_file_mode(active_path)
            return True


def discard_staging(active_path: Path) -> None:
    staging = staging_path_for(active_path)
    staging.unlink(missing_ok=True)
    tmp = staging.with_suffix(staging.suffix + ".tmp")
    tmp.unlink(missing_ok=True)


def delete_active_ca(active_path: Path) -> None:
    """Backup then remove active CA. Staging files are discarded."""
    with _PROCESS_LOCK:
        with _file_lock(lock_path_for(active_path)):
            discard_staging(active_path)
            if active_path.is_file():
                backup = backup_path_for(active_path)
                os.replace(active_path, backup)
            # Leave .bak for rollback/audit; active gone.


def build_ssl_context_for_cafile(cafile: Path) -> ssl.SSLContext:
    if not cafile.is_file():
        raise SyslogCaError("fichier CA absent du conteneur")
    if cafile.name != ACTIVE_BASENAME and cafile.name != STAGING_BASENAME:
        raise SyslogCaError("fichier CA non autorisé")
    # Probe may use staging; worker must only pass ACTIVE (enforced by callers).
    try:
        return ssl.create_default_context(cafile=str(cafile))
    except OSError as exc:
        raise SyslogCaError("permission refusée ou lecture CA impossible") from exc


def probe_tls_handshake(
    *,
    host: str,
    port: int,
    cafile: Path,
    timeout: float = 15.0,
    sock_factory=None,
) -> None:
    """TLS probe using the given cafile (staging or active). Host/port must come from SIEM config."""
    host = (host or "").strip()
    if not host:
        raise SyslogCaError("syslog_host manquant pour le test TLS")
    if not (1 <= int(port) <= 65535):
        raise SyslogCaError("syslog_port invalide")

    ctx = build_ssl_context_for_cafile(cafile)

    def _connect():
        raw = socket.create_connection((host, int(port)), timeout=timeout)
        return ctx.wrap_socket(raw, server_hostname=host)

    connect = sock_factory or _connect
    try:
        with connect() as sock:
            # Touch negotiated cipher to ensure handshake completed.
            _ = sock.cipher()
    except ssl.SSLCertVerificationError as exc:
        raise SyslogCaError(_map_ssl_verify_error(exc)) from exc
    except ssl.SSLError as exc:
        raise SyslogCaError("échec de négociation TLS") from exc
    except TimeoutError as exc:
        raise SyslogCaError("délai dépassé") from exc
    except OSError as exc:
        raise SyslogCaError("refus de connexion") from exc


def _map_ssl_verify_error(exc: ssl.SSLCertVerificationError) -> str:
    msg = (getattr(exc, "verify_message", None) or str(exc) or "").lower()
    if "expired" in msg:
        return "certificat expiré"
    if "not yet valid" in msg:
        return "certificat pas encore valide"
    if "hostname" in msg or "doesn't match" in msg or "ip address mismatch" in msg:
        return "hostname ou IP absente du SAN"
    if "unable to get local issuer" in msg or "self signed" in msg or "unknown ca" in msg:
        return "CA inconnue"
    return "échec de vérification du certificat TLS"


def audit_safe_ca_details(info: CaCertificateInfo | None, **extra: Any) -> dict[str, Any]:
    """Audit payload — never includes PEM or secrets."""
    out: dict[str, Any] = {"destination": "syslog_tls"}
    out.update({k: v for k, v in extra.items() if v is not None})
    if info is not None:
        out.update(
            {
                "subject": info.subject,
                "issuer": info.issuer,
                "fingerprint_sha256": info.fingerprint_sha256,
                "not_after": info.not_after.isoformat(),
            }
        )
    # Belt-and-suspenders: strip any accidental PEM-like keys.
    for banned in ("pem", "pem_bytes", "certificate", "private_key", "content"):
        out.pop(banned, None)
    return out
