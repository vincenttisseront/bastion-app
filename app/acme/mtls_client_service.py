"""Provision / revoke mTLS client apps and rebuild the CA CRL."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.acme.mtls_ca import (
    CLIENT_VALIDITY_DAYS,
    MtlsCaError,
    ca_info,
    client_cn_for_app,
    ensure_self_managed_ca,
    issue_client_certificate,
    request_nginx_reload,
    write_crl,
    write_mtls_nginx_export,
)
from app.audit import log_action
from app.models import MtlsClientApp, utcnow
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"
_APP_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$")


def normalize_app_name(app_name: str) -> str:
    slug = (app_name or "").strip().lower()
    if not _APP_NAME_RE.match(slug):
        raise ValueError(
            "app_name invalide (slug: lettres/chiffres/tirets, 1–64)"
        )
    return slug


def list_mtls_clients(db: Session) -> list[MtlsClientApp]:
    return (
        db.query(MtlsClientApp)
        .order_by(MtlsClientApp.app_name.asc())
        .all()
    )


def get_mtls_client(db: Session, app_name: str) -> MtlsClientApp | None:
    slug = (app_name or "").strip().lower()
    if not slug:
        return None
    return (
        db.query(MtlsClientApp)
        .filter(MtlsClientApp.app_name == slug)
        .first()
    )


def _revoked_entries(db: Session) -> list[tuple[int, datetime]]:
    out: list[tuple[int, datetime]] = []
    rows = (
        db.query(MtlsClientApp)
        .filter(MtlsClientApp.status == STATUS_REVOKED)
        .all()
    )
    for row in rows:
        try:
            serial = int(row.serial_number, 16)
        except ValueError:
            logger.warning(
                "mtls: skip invalid serial for %s", row.app_name
            )
            continue
        revoked_at = row.revoked_at or row.updated_at or utcnow()
        if revoked_at.tzinfo is None:
            revoked_at = revoked_at.replace(tzinfo=timezone.utc)
        out.append((serial, revoked_at))
    return out


def rebuild_crl_and_export(
    db: Session, settings: Settings, *, reload_nginx: bool = True
) -> tuple[bool, str]:
    ensure_self_managed_ca(settings)
    write_crl(settings, revoked=_revoked_entries(db))
    write_mtls_nginx_export(settings)
    if not reload_nginx:
        return True, "CRL + nginx export écrits"
    return request_nginx_reload(settings)


def provision_mtls_client(
    db: Session,
    settings: Settings,
    *,
    app_name: str,
    actor: str,
    validity_days: int = CLIENT_VALIDITY_DAYS,
) -> MtlsClientApp:
    """Issue (or re-issue) an active client cert for ``app_name``."""
    slug = normalize_app_name(app_name)
    ensure_self_managed_ca(settings)
    existing = get_mtls_client(db, slug)
    if existing is not None and existing.status == STATUS_ACTIVE:
        raise ValueError(f"application mTLS déjà active: {slug}")

    try:
        cert, _cert_pem, _key_pem, _bundle = issue_client_certificate(
            settings, app_name=slug, validity_days=validity_days
        )
    except MtlsCaError as exc:
        raise ValueError(str(exc)) from exc

    not_after = (
        cert.not_valid_after_utc
        if hasattr(cert, "not_valid_after_utc")
        else cert.not_valid_after.replace(tzinfo=timezone.utc)
    )
    serial_hex = f"{cert.serial_number:x}"
    cn = client_cn_for_app(slug)

    if existing is None:
        row = MtlsClientApp(
            app_name=slug,
            cn=cn,
            status=STATUS_ACTIVE,
            serial_number=serial_hex,
            valid_until=not_after,
            issued_at=utcnow(),
            revoked_at=None,
            updated_at=utcnow(),
        )
        db.add(row)
    else:
        # Re-issue after prior revoke
        row = existing
        row.cn = cn
        row.status = STATUS_ACTIVE
        row.serial_number = serial_hex
        row.valid_until = not_after
        row.issued_at = utcnow()
        row.revoked_at = None
        row.updated_at = utcnow()

    db.commit()
    db.refresh(row)
    rebuild_crl_and_export(db, settings, reload_nginx=True)
    log_action(
        db,
        actor=actor,
        action="mtls.client_provisioned",
        target=slug,
        details={"cn": cn, "serial": serial_hex},
    )
    return row


def revoke_mtls_client(
    db: Session,
    settings: Settings,
    *,
    app_name: str,
    actor: str,
) -> MtlsClientApp:
    slug = normalize_app_name(app_name)
    row = get_mtls_client(db, slug)
    if row is None:
        raise ValueError(f"application mTLS inconnue: {slug}")
    if row.status == STATUS_REVOKED:
        return row

    row.status = STATUS_REVOKED
    row.revoked_at = utcnow()
    row.updated_at = utcnow()
    db.commit()
    db.refresh(row)
    ok, detail = rebuild_crl_and_export(db, settings, reload_nginx=True)
    log_action(
        db,
        actor=actor,
        action="mtls.client_revoked",
        target=slug,
        details={
            "cn": row.cn,
            "serial": row.serial_number,
            "reload_ok": ok,
            "reload_detail": (detail or "")[:200],
        },
    )
    return row


def mtls_dashboard_payload(
    db: Session, settings: Settings
) -> dict[str, Any]:
    ensure_self_managed_ca(settings)
    info = ca_info(settings)
    clients = list_mtls_clients(db)
    return {
        "ca": None
        if info is None
        else {
            "subject": info.subject,
            "fingerprint_sha256": info.fingerprint_sha256,
            "not_before": info.not_before.isoformat(),
            "not_after": info.not_after.isoformat(),
            "serial_hex": info.serial_hex,
            "path": info.path,
        },
        "clients": [
            {
                "app_name": c.app_name,
                "cn": c.cn,
                "status": c.status,
                "serial_number": c.serial_number,
                "valid_until": c.valid_until.isoformat()
                if c.valid_until
                else None,
                "issued_at": c.issued_at.isoformat() if c.issued_at else None,
                "revoked_at": c.revoked_at.isoformat()
                if c.revoked_at
                else None,
            }
            for c in clients
        ],
        "counts": {
            "total": len(clients),
            "active": sum(1 for c in clients if c.status == STATUS_ACTIVE),
            "revoked": sum(1 for c in clients if c.status == STATUS_REVOKED),
        },
    }
