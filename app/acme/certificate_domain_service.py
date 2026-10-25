"""Persist and sync CertificateDomain rows for hybrid ACME (DNS-01 / HTTP-01)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from sqlalchemy.orm import Session

from app.acme.settings_service import (
    RENEW_SOON_DAYS,
    certs_dir,
    ensure_acme_settings,
    get_acme_config,
    resolve_cf_token,
)
from app.bastion.acme_domains_export import build_acme_domains_manifest
from app.bastion.nginx_known_hosts_export import normalize_hostname
from app.models import CertificateDomain, utcnow
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

PROVIDER_DNS = "dns_cloudflare"
PROVIDER_HTTP = "http_native"
PROVIDERS = frozenset({PROVIDER_DNS, PROVIDER_HTTP})

STATUS_PENDING = "pending"
STATUS_VALID = "valid"
STATUS_EXPIRED = "expired"
STATUS_FAILED = "failed"
STATUSES = frozenset(
    {STATUS_PENDING, STATUS_VALID, STATUS_EXPIRED, STATUS_FAILED}
)

CHALLENGE_BY_PROVIDER = {
    PROVIDER_DNS: "dns-01",
    PROVIDER_HTTP: "http-01",
}


def is_wildcard(domain: str) -> bool:
    host = (domain or "").strip().lower()
    return host.startswith("*.")


def default_provider_type(db: Session, settings: Settings) -> str:
    """Prefer DNS-01 when ACME + Cloudflare token are ready; else HTTP-01."""
    cfg = get_acme_config(db)
    if cfg.enabled and (
        cfg.cf_token_configured or resolve_cf_token(db, settings)
    ):
        return PROVIDER_DNS
    return PROVIDER_HTTP


def resolve_provider_for_domain(
    db: Session,
    settings: Settings,
    domain: str,
    *,
    existing: CertificateDomain | None = None,
) -> str:
    host = normalize_hostname(domain) or (domain or "").strip().lower()
    if is_wildcard(host):
        return PROVIDER_DNS
    if existing is not None and (existing.provider_type or "") in PROVIDERS:
        return existing.provider_type
    return default_provider_type(db, settings)


def get_certificate_domain(db: Session, domain: str) -> CertificateDomain | None:
    host = normalize_hostname(domain) or (domain or "").strip().lower()
    if not host:
        return None
    return (
        db.query(CertificateDomain)
        .filter(CertificateDomain.domain == host)
        .first()
    )


def list_certificate_domains(db: Session) -> list[CertificateDomain]:
    return (
        db.query(CertificateDomain)
        .order_by(CertificateDomain.domain.asc())
        .all()
    )


def _read_not_after(cert_path: Path) -> datetime | None:
    try:
        cert = x509.load_pem_x509_certificate(
            cert_path.read_bytes(), default_backend()
        )
        if hasattr(cert, "not_valid_after_utc"):
            return cert.not_valid_after_utc
        return cert.not_valid_after.replace(tzinfo=timezone.utc)
    except Exception as exc:
        logger.warning("acme: cannot parse cert %s: %s", cert_path, exc)
        return None


def refresh_row_from_disk(
    row: CertificateDomain,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> CertificateDomain:
    """Update status / valid_until from on-disk PEM (no secrets stored)."""
    now = now or datetime.now(timezone.utc)
    cert_path = certs_dir(settings) / row.domain / "fullchain.pem"
    key_path = certs_dir(settings) / row.domain / "privkey.pem"
    if not (cert_path.is_file() and key_path.is_file()):
        if row.status != STATUS_FAILED:
            row.status = STATUS_PENDING
        row.valid_until = None
        row.updated_at = utcnow()
        return row

    not_after = _read_not_after(cert_path)
    row.valid_until = not_after
    if not_after is None:
        row.status = STATUS_FAILED
        row.last_error = "certificate parse failed"
    elif not_after <= now:
        row.status = STATUS_EXPIRED
        row.last_error = None
    else:
        row.status = STATUS_VALID
        row.last_error = None
    row.updated_at = utcnow()
    return row


def mark_failed(db: Session, domain: str, error: str) -> CertificateDomain | None:
    row = get_certificate_domain(db, domain)
    if row is None:
        return None
    # Never persist key material — truncate and scrub common PEM markers.
    msg = (error or "unknown error").replace("-----BEGIN", "[redacted]")
    row.status = STATUS_FAILED
    row.last_error = msg[:2000]
    row.updated_at = utcnow()
    db.commit()
    db.refresh(row)
    return row


def mark_valid_from_disk(
    db: Session, settings: Settings, domain: str
) -> CertificateDomain | None:
    row = get_certificate_domain(db, domain)
    if row is None:
        return None
    refresh_row_from_disk(row, settings)
    if row.status == STATUS_VALID:
        row.last_error = None
    db.commit()
    db.refresh(row)
    return row


def set_provider_type(
    db: Session, domain: str, provider_type: str
) -> CertificateDomain:
    host = normalize_hostname(domain) or (domain or "").strip().lower()
    if not host:
        raise ValueError("domaine invalide")
    provider = (provider_type or "").strip()
    if provider not in PROVIDERS:
        raise ValueError(f"provider_type invalide: {provider_type}")
    if is_wildcard(host) and provider != PROVIDER_DNS:
        raise ValueError("les wildcards exigent dns_cloudflare")
    row = get_certificate_domain(db, host)
    if row is None:
        row = CertificateDomain(
            domain=host,
            provider_type=provider,
            status=STATUS_PENDING,
            updated_at=utcnow(),
        )
        db.add(row)
    else:
        row.provider_type = provider
        row.updated_at = utcnow()
    db.commit()
    db.refresh(row)
    return row


def sync_certificate_domains_from_manifest(
    db: Session, settings: Settings
) -> list[CertificateDomain]:
    """Upsert CertificateDomain for every FQDN in the ACME manifest."""
    ensure_acme_settings(db)
    manifest = build_acme_domains_manifest(db, settings)
    now = datetime.now(timezone.utc)
    seen: set[str] = set()
    rows: list[CertificateDomain] = []

    for entry in manifest.get("domains") or []:
        if not isinstance(entry, dict):
            continue
        host = normalize_hostname(str(entry.get("fqdn") or ""))
        if not host or host in seen:
            continue
        seen.add(host)
        existing = get_certificate_domain(db, host)
        provider = resolve_provider_for_domain(
            db, settings, host, existing=existing
        )
        # Manifest may already carry an explicit provider (after export enrichment).
        explicit = str(entry.get("provider") or "").strip()
        if explicit in PROVIDERS and not is_wildcard(host):
            if existing is None or existing.provider_type == explicit:
                provider = explicit
            elif existing is not None:
                provider = existing.provider_type

        if existing is None:
            row = CertificateDomain(
                domain=host,
                provider_type=provider,
                status=STATUS_PENDING,
                updated_at=utcnow(),
            )
            db.add(row)
        else:
            row = existing
            # Preserve admin-chosen provider; only fill default on first create.
            if not (row.provider_type or "").strip():
                row.provider_type = provider
        refresh_row_from_disk(row, settings, now=now)
        rows.append(row)

    db.commit()
    for row in rows:
        db.refresh(row)
    return rows


def domains_needing_attention(
    db: Session, *, within_days: int = RENEW_SOON_DAYS
) -> list[CertificateDomain]:
    """Rows that should raise an Ops alert (expired, failed, pending, renew soon)."""
    now = datetime.now(timezone.utc)
    out: list[CertificateDomain] = []
    for row in list_certificate_domains(db):
        if row.status in (STATUS_EXPIRED, STATUS_FAILED, STATUS_PENDING):
            out.append(row)
            continue
        if row.valid_until is None:
            out.append(row)
            continue
        vu = row.valid_until
        if vu.tzinfo is None:
            vu = vu.replace(tzinfo=timezone.utc)
        days_left = (vu - now).days
        if days_left <= within_days:
            out.append(row)
    return out


def provider_challenge(provider_type: str) -> str:
    return CHALLENGE_BY_PROVIDER.get(provider_type, "dns-01")


def certificate_domain_to_dict(row: CertificateDomain) -> dict[str, Any]:
    days_left: int | None = None
    if row.valid_until is not None:
        vu = row.valid_until
        if vu.tzinfo is None:
            vu = vu.replace(tzinfo=timezone.utc)
        days_left = (vu - datetime.now(timezone.utc)).days
    return {
        "domain": row.domain,
        "provider_type": row.provider_type,
        "challenge": provider_challenge(row.provider_type),
        "status": row.status,
        "valid_until": row.valid_until.isoformat() if row.valid_until else None,
        "days_left": days_left,
        "last_error": row.last_error,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "renew_due": _renew_due(row),
    }


def _renew_due(row: CertificateDomain) -> bool:
    if row.status in (STATUS_EXPIRED, STATUS_FAILED, STATUS_PENDING):
        return True
    if row.valid_until is None:
        return True
    vu = row.valid_until
    if vu.tzinfo is None:
        vu = vu.replace(tzinfo=timezone.utc)
    return (vu - datetime.now(timezone.utc)).days <= RENEW_SOON_DAYS
