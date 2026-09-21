"""SIEM Syslog TLS CA install / delete / status (staged probe then commit)."""

from __future__ import annotations

import logging
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import SiemForwardingSettings, utcnow
from app.siem import syslog_ca as ca
from app.siem.settings_service import ensure_siem_settings, get_siem_config
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

ProbeFn = Callable[..., None]

_ACTION_ROLLBACK = "siem.syslog_ca.rollback"
_ACTION_VALIDATION_FAILED = "siem.syslog_ca.validation_failed"
_ACTION_REPLACE = "siem.syslog_ca.replace"
_ACTION_IMPORT = "siem.syslog_ca.import"
_ACTION_DELETE = "siem.syslog_ca.delete"
_ACTION_TEST = "siem.syslog_ca.test"
_TARGET_SYSLOG_TLS = "syslog_tls"


def _clear_ca_db_fields(row: SiemForwardingSettings) -> None:
    row.syslog_ca_relative_path = None
    row.syslog_ca_logical_name = None
    row.syslog_ca_subject = None
    row.syslog_ca_issuer = None
    row.syslog_ca_fingerprint_sha256 = None
    row.syslog_ca_not_before = None
    row.syslog_ca_not_after = None
    row.syslog_ca_uploaded_at = None
    row.syslog_ca_uploaded_by = None


def _apply_ca_db_fields(
    row: SiemForwardingSettings,
    *,
    info: ca.CaCertificateInfo,
    relative_path: str,
    logical_name: str,
    actor: str,
) -> None:
    row.syslog_ca_relative_path = relative_path
    row.syslog_ca_logical_name = logical_name
    row.syslog_ca_subject = info.subject
    row.syslog_ca_issuer = info.issuer
    row.syslog_ca_fingerprint_sha256 = info.fingerprint_sha256
    row.syslog_ca_not_before = info.not_before
    row.syslog_ca_not_after = info.not_after
    row.syslog_ca_uploaded_at = utcnow()
    row.syslog_ca_uploaded_by = actor
    # Never persist tls_verify=false for syslog TLS.
    row.syslog_tls_verify = True
    row.updated_at = utcnow()
    row.updated_by = actor


def _snapshot_ca_db_meta(row: SiemForwardingSettings) -> dict[str, Any]:
    return {
        "syslog_ca_relative_path": row.syslog_ca_relative_path,
        "syslog_ca_logical_name": row.syslog_ca_logical_name,
        "syslog_ca_subject": row.syslog_ca_subject,
        "syslog_ca_issuer": row.syslog_ca_issuer,
        "syslog_ca_fingerprint_sha256": row.syslog_ca_fingerprint_sha256,
        "syslog_ca_not_before": row.syslog_ca_not_before,
        "syslog_ca_not_after": row.syslog_ca_not_after,
        "syslog_ca_uploaded_at": row.syslog_ca_uploaded_at,
        "syslog_ca_uploaded_by": row.syslog_ca_uploaded_by,
    }


def _restore_ca_db_meta(row: SiemForwardingSettings, prev_meta: dict[str, Any]) -> None:
    for key, val in prev_meta.items():
        setattr(row, key, val)


def _audit_ca(
    db: Session,
    *,
    actor: str,
    action: str,
    info: ca.CaCertificateInfo | None,
    ip_address: str | None,
    **detail_kw: Any,
) -> None:
    log_action(
        db,
        actor=actor,
        action=action,
        target=_TARGET_SYSLOG_TLS,
        details=ca.audit_safe_ca_details(info, **detail_kw),
        ip_address=ip_address,
        forward_to_siem=False,
    )


def get_ca_api_status(db: Session, settings: Settings) -> dict[str, Any]:
    row = ensure_siem_settings(db)
    rel = (row.syslog_ca_relative_path or "").strip() or ca.DEFAULT_RELATIVE_PATH
    derived = ca.derive_ca_status(settings, relative_path=rel)
    # Prefer live file meta; enrich with import audit fields from DB when fingerprints match.
    out: dict[str, Any] = {
        "configured": bool(derived.get("configured")),
        "valid": bool(derived.get("valid")),
        "badge": derived.get("badge") or "missing",
        "tls_verify": True,
        "relative_path": derived.get("relative_path"),
        "subject": derived.get("subject"),
        "issuer": derived.get("issuer"),
        "fingerprint_sha256": derived.get("fingerprint_sha256"),
        "not_before": derived.get("not_before"),
        "not_after": derived.get("not_after"),
        "logical_name": row.syslog_ca_logical_name,
        "uploaded_at": row.syslog_ca_uploaded_at.isoformat()
        if row.syslog_ca_uploaded_at
        else None,
        "uploaded_by": row.syslog_ca_uploaded_by,
        "error": derived.get("error"),
    }
    fp_file = derived.get("fingerprint_sha256")
    fp_db = (row.syslog_ca_fingerprint_sha256 or "").strip()
    if fp_file and fp_db and fp_file != fp_db:
        # File is source of truth; DB meta may be stale.
        out["badge"] = "configured"
    if not derived.get("configured"):
        # Clear misleading DB-only fields when file missing.
        out["logical_name"] = None
        out["uploaded_at"] = None
        out["uploaded_by"] = None
    return out


def _probe_staging_or_raise(
    *,
    cfg: Any,
    active: Any,
    staging: Any,
    probe_fn: ProbeFn | None,
    skip_tls_probe: bool,
) -> None:
    if skip_tls_probe:
        return
    if cfg.protocol != "syslog_tls" or not cfg.syslog_host:
        ca.discard_staging(active)
        raise ca.SyslogCaError(
            "configurez et enregistrez l’hôte Syslog TLS avant d’importer la CA"
        )
    probe = probe_fn or ca.probe_tls_handshake
    probe(
        host=cfg.syslog_host,
        port=cfg.syslog_port,
        cafile=staging,
    )


def _persist_ca_db_or_rollback(
    db: Session,
    row: SiemForwardingSettings,
    *,
    info: ca.CaCertificateInfo,
    relative_path: str,
    logical_name: str,
    actor: str,
    prev_meta: dict[str, Any],
    active: Any,
    ip_address: str | None,
) -> None:
    try:
        _apply_ca_db_fields(
            row,
            info=info,
            relative_path=relative_path,
            logical_name=logical_name,
            actor=actor,
        )
        db.commit()
        db.refresh(row)
    except Exception:
        logger.exception("siem syslog CA DB update failed — restoring file")
        ca.rollback_active_from_backup(active)
        _restore_ca_db_meta(row, prev_meta)
        try:
            db.rollback()
        except Exception:
            logger.exception("siem syslog CA DB rollback failed")
        _audit_ca(
            db,
            actor=actor,
            action=_ACTION_ROLLBACK,
            info=info,
            ip_address=ip_address,
            result="error",
            reason="db_update_failed",
        )
        raise ca.SyslogCaError("échec de mise à jour de la configuration CA") from None


def _cleanup_failed_install(
    db: Session,
    *,
    active: Any,
    committed: bool,
    replacing: bool,
    info: ca.CaCertificateInfo,
    actor: str,
    ip_address: str | None,
    exc: ca.SyslogCaError,
) -> None:
    ca.discard_staging(active)
    if committed:
        ca.rollback_active_from_backup(active)
    _audit_ca(
        db,
        actor=actor,
        action=_ACTION_ROLLBACK if replacing else _ACTION_VALIDATION_FAILED,
        info=info,
        ip_address=ip_address,
        result="error",
        error=str(exc),
    )


def install_syslog_ca(
    db: Session,
    settings: Settings,
    *,
    raw: bytes,
    filename: str | None,
    actor: str,
    ip_address: str | None = None,
    probe_fn: ProbeFn | None = None,
    skip_tls_probe: bool = False,
) -> dict[str, Any]:
    """Validate → staging → TLS probe → atomic commit → transactional DB update."""
    row = ensure_siem_settings(db)
    replacing = bool(
        (row.syslog_ca_relative_path or "").strip()
        and ca.is_active_ca_valid(
            settings, relative_path=row.syslog_ca_relative_path or ca.DEFAULT_RELATIVE_PATH
        )
    )
    action = _ACTION_REPLACE if replacing else _ACTION_IMPORT

    try:
        info = ca.parse_and_validate_ca_pem(raw)
    except ca.SyslogCaError as exc:
        _audit_ca(
            db,
            actor=actor,
            action=_ACTION_VALIDATION_FAILED,
            info=None,
            ip_address=ip_address,
            result="error",
            error=str(exc),
        )
        raise

    relative_path = ca.DEFAULT_RELATIVE_PATH
    logical_name = ca.sanitize_logical_name(filename)
    active = ca.resolve_ca_path(settings, relative_path=relative_path)
    cfg = get_siem_config(db, settings=settings)
    prev_meta = _snapshot_ca_db_meta(row)

    staging = None
    committed = False
    db_rolled_back = False
    try:
        staging = ca.write_staging_ca(active, info.pem_bytes)
        _probe_staging_or_raise(
            cfg=cfg,
            active=active,
            staging=staging,
            probe_fn=probe_fn,
            skip_tls_probe=skip_tls_probe,
        )
        ca.commit_staging_to_active(
            active, expected_fingerprint=info.fingerprint_sha256
        )
        committed = True

        try:
            _persist_ca_db_or_rollback(
                db,
                row,
                info=info,
                relative_path=relative_path,
                logical_name=logical_name,
                actor=actor,
                prev_meta=prev_meta,
                active=active,
                ip_address=ip_address,
            )
        except ca.SyslogCaError:
            db_rolled_back = True
            raise

        _audit_ca(
            db,
            actor=actor,
            action=action,
            info=info,
            ip_address=ip_address,
            result="ok",
        )
        return get_ca_api_status(db, settings)

    except ca.SyslogCaError as exc:
        if not db_rolled_back:
            _cleanup_failed_install(
                db,
                active=active,
                committed=committed,
                replacing=replacing,
                info=info,
                actor=actor,
                ip_address=ip_address,
                exc=exc,
            )
        raise
    except Exception:
        ca.discard_staging(active)
        if committed and not db_rolled_back:
            ca.rollback_active_from_backup(active)
        _audit_ca(
            db,
            actor=actor,
            action=_ACTION_ROLLBACK,
            info=None,
            ip_address=ip_address,
            result="error",
            reason="unexpected",
        )
        raise


def delete_syslog_ca(
    db: Session,
    settings: Settings,
    *,
    actor: str,
    ip_address: str | None = None,
) -> dict[str, Any]:
    row = ensure_siem_settings(db)
    rel = (row.syslog_ca_relative_path or "").strip() or ca.DEFAULT_RELATIVE_PATH
    info = None
    try:
        active = ca.resolve_ca_path(settings, relative_path=rel)
        if active.is_file():
            try:
                info = ca.read_ca_file_info(active)
            except ca.SyslogCaError:
                info = None
            ca.delete_active_ca(active)
    except ca.SyslogCaError:
        active = None

    _clear_ca_db_fields(row)
    # Keep tls_verify=True forever for syslog intent; operationality comes from file.
    row.syslog_tls_verify = True
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()

    _audit_ca(
        db,
        actor=actor,
        action=_ACTION_DELETE,
        info=info,
        ip_address=ip_address,
        result="ok",
    )
    return get_ca_api_status(db, settings)


def _tls_ca_test_precheck(cfg: Any) -> str | None:
    """Return error message if preconditions fail, else None."""
    if cfg.protocol != "syslog_tls":
        return "protocole Syslog TCP+TLS requis"
    if not cfg.syslog_host:
        return "syslog_host manquant dans la configuration SIEM active"
    if not cfg.syslog_tls_verify:
        return "tls_verify=false n’est pas supporté pour Syslog TCP+TLS"
    if not cfg.syslog_ca_valid or not cfg.syslog_ca_relative_path:
        return "aucune CA Syslog TLS valide configurée"
    return None


def run_syslog_tls_ca_test(
    db: Session,
    settings: Settings,
    *,
    actor: str,
    ip_address: str | None = None,
    sock_factory=None,
) -> tuple[bool, str, list[str]]:
    """TLS-only probe against active SIEM host/port + active CA file (not staging)."""
    lines: list[str] = ["$ bastion siem syslog-tls-ca-test"]
    cfg = get_siem_config(db, settings=settings)
    lines.append(f"protocol={cfg.protocol} host={cfg.syslog_host}:{cfg.syslog_port}")

    precheck = _tls_ca_test_precheck(cfg)
    if precheck:
        lines.append(f"✗ {precheck}")
        return False, precheck, lines

    try:
        active = ca.resolve_ca_path(
            settings, relative_path=cfg.syslog_ca_relative_path
        )
        if active.name != ca.ACTIVE_BASENAME:
            raise ca.SyslogCaError("fichier CA non autorisé")
        ca.probe_tls_handshake(
            host=cfg.syslog_host,
            port=cfg.syslog_port,
            cafile=active,
            sock_factory=sock_factory,
        )
    except ca.SyslogCaError as exc:
        msg = str(exc)
        lines.append(f"✗ {msg}")
        _audit_ca(
            db,
            actor=actor,
            action=_ACTION_TEST,
            info=None,
            ip_address=ip_address,
            result="error",
            error=msg,
        )
        return False, msg, lines

    msg = "Négociation TLS OK avec la CA active"
    lines.append(f"✓ {msg}")
    _audit_ca(
        db,
        actor=actor,
        action=_ACTION_TEST,
        info=None,
        ip_address=ip_address,
        result="ok",
    )
    return True, msg, lines
