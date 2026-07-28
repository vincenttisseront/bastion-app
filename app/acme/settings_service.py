"""DB-backed AcmeSettings singleton + cert status for Admin → ACME."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from sqlalchemy.orm import Session

from app.audit import log_action
from app.bastion.acme_domains_export import build_acme_domains_manifest, write_acme_domains_export
from app.models import AcmeSettings, utcnow
from app.secret_crypto import decrypt_secret, encrypt_secret, encryption_configured
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

ACME_SETTINGS_ID = 1
DNS_APIS = frozenset({"dns_cf"})
ACME_CAS = frozenset({"letsencrypt", "letsencrypt_test"})
RENEW_SOON_DAYS = 30
RECONCILE_LOG_NAME = "acme-reconcile.log"
LAST_RUN_JSON_NAME = "acme-last-run.json"
DEFAULT_LOG_TAIL_BYTES = 48_000


@dataclass(frozen=True)
class AcmeConfigView:
    enabled: bool
    dns_api: str
    acme_ca: str
    cf_token_configured: bool
    cf_account_id: str
    cf_zone_id: str
    last_reconcile_at: datetime | None
    last_reconcile_status: str | None
    last_reconcile_message: str | None
    updated_at: datetime | None
    updated_by: str | None


@dataclass(frozen=True)
class AcmeDomainStatus:
    fqdn: str
    slug: str
    family: str
    upstream_url: str
    has_cert: bool
    is_placeholder: bool
    not_before: datetime | None
    not_after: datetime | None
    days_left: int | None
    renew_due: bool
    issuer: str | None
    status: str  # missing | ok | renew_soon | expired | placeholder


def ensure_acme_settings(db: Session) -> AcmeSettings:
    row = db.query(AcmeSettings).filter_by(id=ACME_SETTINGS_ID).first()
    if row is not None:
        return row
    row = AcmeSettings(
        id=ACME_SETTINGS_ID,
        enabled=False,
        dns_api="dns_cf",
        acme_ca="letsencrypt",
        cf_token_encrypted=None,
        cf_account_id="",
        cf_zone_id="",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def get_acme_config(db: Session) -> AcmeConfigView:
    row = ensure_acme_settings(db)
    return AcmeConfigView(
        enabled=bool(row.enabled),
        dns_api=(row.dns_api or "dns_cf").strip(),
        acme_ca=(row.acme_ca or "letsencrypt").strip(),
        cf_token_configured=bool((row.cf_token_encrypted or "").strip()),
        cf_account_id=(row.cf_account_id or "").strip(),
        cf_zone_id=(row.cf_zone_id or "").strip(),
        last_reconcile_at=row.last_reconcile_at,
        last_reconcile_status=row.last_reconcile_status,
        last_reconcile_message=row.last_reconcile_message,
        updated_at=row.updated_at,
        updated_by=row.updated_by,
    )


def resolve_cf_token(db: Session, settings: Settings) -> str | None:
    """DB Fernet token first, then env CF_Token (bootstrap / .env.acme)."""
    row = ensure_acme_settings(db)
    cipher = (row.cf_token_encrypted or "").strip()
    if cipher:
        try:
            return decrypt_secret(cipher, settings)
        except Exception:
            logger.warning("acme: failed to decrypt cf_token_encrypted")
            return None
    env = (os.environ.get("CF_Token") or os.environ.get("CF_Token_Write") or "").strip()
    return env or None


def certs_dir(settings: Settings) -> Path:
    """Certs live next to portal data (compose: SSO_PORTAL_DATA_DIR/certs)."""
    data = Path(settings.portal_data_dir or "/var/lib/sso-portal")
    return data / "certs"


def _read_cert_meta(cert_path: Path) -> dict[str, Any]:
    raw = cert_path.read_bytes()
    cert = x509.load_pem_x509_certificate(raw, default_backend())
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    issuer = cert.issuer.rfc4514_string()
    try:
        is_placeholder = cert.issuer == cert.subject
    except Exception:
        issuer_l = issuer.lower()
        is_placeholder = "let's encrypt" not in issuer_l and "lets encrypt" not in issuer_l
    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days
    return {
        "not_before": not_before,
        "not_after": not_after,
        "days_left": days_left,
        "issuer": issuer,
        "is_placeholder": is_placeholder,
    }


def list_domain_statuses(db: Session, settings: Settings) -> list[AcmeDomainStatus]:
    manifest = build_acme_domains_manifest(db, settings)
    root = certs_dir(settings)
    out: list[AcmeDomainStatus] = []
    now = datetime.now(timezone.utc)
    for entry in manifest.get("domains", []):
        fqdn = str(entry.get("fqdn") or "").strip()
        if not fqdn:
            continue
        cert_path = root / fqdn / "fullchain.pem"
        key_path = root / fqdn / "privkey.pem"
        has_cert = cert_path.is_file() and key_path.is_file()
        meta: dict[str, Any] = {}
        if has_cert:
            try:
                meta = _read_cert_meta(cert_path)
            except Exception as exc:
                logger.warning("acme: cannot parse cert for %s: %s", fqdn, exc)
                has_cert = False

        days_left = meta.get("days_left")
        is_placeholder = bool(meta.get("is_placeholder"))
        not_after = meta.get("not_after")
        if not has_cert:
            status = "missing"
            renew_due = True
        elif is_placeholder:
            status = "placeholder"
            renew_due = True
        elif isinstance(not_after, datetime) and not_after <= now:
            status = "expired"
            renew_due = True
        elif isinstance(days_left, int) and days_left <= RENEW_SOON_DAYS:
            status = "renew_soon"
            renew_due = True
        else:
            status = "ok"
            renew_due = False

        out.append(
            AcmeDomainStatus(
                fqdn=fqdn,
                slug=str(entry.get("slug") or ""),
                family=str(entry.get("family") or "public_proxy"),
                upstream_url=str(entry.get("upstream_url") or ""),
                has_cert=has_cert,
                is_placeholder=is_placeholder,
                not_before=meta.get("not_before"),
                not_after=not_after if isinstance(not_after, datetime) else None,
                days_left=days_left if isinstance(days_left, int) else None,
                renew_due=renew_due,
                issuer=meta.get("issuer"),
                status=status,
            )
        )
    return out


def write_acme_runtime_env(db: Session, settings: Settings) -> Path:
    """Write exports/acme-runtime.env for acme-companion (sourced by reconcile)."""
    exports = Path(settings.exports_dir)
    exports.mkdir(parents=True, exist_ok=True)
    path = exports / "acme-runtime.env"
    cfg = get_acme_config(db)
    lines = [
        "# Generated by bastion-app Admin → ACME — do not edit by hand",
        f"ACME_DNS_API={cfg.dns_api}",
        f"ACME_CA={cfg.acme_ca}",
        f"ACME_ENABLED={'1' if cfg.enabled else '0'}",
    ]
    if cfg.cf_account_id:
        lines.append(f"CF_Account_ID={cfg.cf_account_id}")
    if cfg.cf_zone_id:
        lines.append(f"CF_Zone_ID={cfg.cf_zone_id}")
    token = resolve_cf_token(db, settings) if cfg.enabled else None
    if token:
        # Escape for shell sourcing: wrap in single quotes, escape embedded quotes
        safe = token.replace("'", "'\"'\"'")
        lines.append(f"CF_Token='{safe}'")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def update_acme_settings(
    db: Session,
    settings: Settings,
    *,
    enabled: bool,
    dns_api: str,
    acme_ca: str,
    cf_account_id: str,
    cf_zone_id: str,
    cf_token: str | None,
    clear_cf_token: bool,
    actor: str,
) -> AcmeSettings:
    row = ensure_acme_settings(db)
    dns = (dns_api or "dns_cf").strip()
    if dns not in DNS_APIS:
        raise ValueError(f"dns_api non supporté: {dns}")
    ca = (acme_ca or "letsencrypt").strip()
    if ca not in ACME_CAS:
        raise ValueError(f"acme_ca invalide: {ca}")

    row.enabled = bool(enabled)
    row.dns_api = dns
    row.acme_ca = ca
    row.cf_account_id = (cf_account_id or "").strip()
    row.cf_zone_id = (cf_zone_id or "").strip()
    row.updated_by = actor
    row.updated_at = utcnow()

    if clear_cf_token:
        row.cf_token_encrypted = None
    elif cf_token is not None and cf_token.strip():
        if not encryption_configured(settings):
            raise ValueError("Chiffrement Fernet non configuré — impossible de stocker le token CF")
        row.cf_token_encrypted = encrypt_secret(cf_token.strip(), settings)

    db.commit()
    db.refresh(row)

    write_acme_domains_export(db, settings)
    write_acme_runtime_env(db, settings)

    log_action(
        db,
        actor=actor,
        action="acme.settings_updated",
        target="acme_settings",
        details={
            "enabled": row.enabled,
            "dns_api": row.dns_api,
            "acme_ca": row.acme_ca,
            "cf_token_configured": bool(row.cf_token_encrypted),
            "cf_zone_set": bool(row.cf_zone_id),
        },
    )
    return row


def record_reconcile_result(
    db: Session,
    *,
    status: str,
    message: str,
    actor: str,
) -> AcmeSettings:
    row = ensure_acme_settings(db)
    row.last_reconcile_at = utcnow()
    row.last_reconcile_status = status
    row.last_reconcile_message = (message or "")[:2000]
    row.updated_by = actor
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="acme.reconcile",
        target="acme_settings",
        details={"status": status, "message": message[:500]},
    )
    return row


def trigger_reconcile(db: Session, settings: Settings, *, actor: str) -> tuple[bool, str]:
    """Export domains + runtime env and signal acme-companion via certs sentinel.

    bastion-app never talks to the Docker socket (security). The sidecar polls
    ``certs/.reconcile_request`` every few seconds and runs reconcile-certs.sh.
    """
    write_acme_domains_export(db, settings)
    write_acme_runtime_env(db, settings)
    cfg = get_acme_config(db)
    if not cfg.enabled:
        record_reconcile_result(
            db, status="error", message="ACME désactivé — activez-le avant de réconcilier", actor=actor
        )
        return False, "ACME est désactivé"

    sentinel = certs_dir(settings) / ".reconcile_request"
    try:
        certs_dir(settings).mkdir(parents=True, exist_ok=True)
        sentinel.write_text(utcnow().isoformat(), encoding="utf-8")
    except OSError as exc:
        msg = f"Impossible d'écrire le signal pour acme-companion: {exc}"
        record_reconcile_result(db, status="error", message=msg, actor=actor)
        return False, msg

    n_domains = len(build_acme_domains_manifest(db, settings).get("domains") or [])
    msg = (
        f"Demande envoyée à acme-companion ({n_domains} domaine(s)). "
        "Émission DNS-01 automatique via API Cloudflare (pas de TXT manuel) — "
        "suivez les logs en direct sur cette page."
    )
    record_reconcile_result(db, status="pending", message=msg, actor=actor)
    return True, msg


def read_acme_reconcile_log(settings: Settings, *, max_bytes: int = DEFAULT_LOG_TAIL_BYTES) -> dict[str, Any]:
    """Tail of sidecar reconcile log (shared certs volume)."""
    path = certs_dir(settings) / RECONCILE_LOG_NAME
    if not path.is_file():
        return {
            "path": str(path),
            "exists": False,
            "text": "",
            "size": 0,
            "truncated": False,
        }
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
                raw = fh.read()
                truncated = True
            else:
                raw = fh.read()
                truncated = False
        text = raw.decode("utf-8", errors="replace")
        if truncated:
            # Drop partial first line
            nl = text.find("\n")
            if nl >= 0:
                text = text[nl + 1 :]
        return {
            "path": str(path),
            "exists": True,
            "text": text,
            "size": size,
            "truncated": truncated,
        }
    except OSError as exc:
        logger.warning("acme: cannot read reconcile log: %s", exc)
        return {
            "path": str(path),
            "exists": True,
            "text": f"(erreur lecture log: {exc})",
            "size": 0,
            "truncated": False,
        }


def read_acme_last_run(settings: Settings) -> dict[str, Any] | None:
    path = certs_dir(settings) / LAST_RUN_JSON_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("acme: cannot read last-run json: %s", exc)
        return None


def sidecar_running(settings: Settings) -> bool:
    return (certs_dir(settings) / ".reconcile_running").is_file()


def sync_reconcile_from_sidecar(db: Session, settings: Settings, *, actor: str = "acme-sidecar") -> bool:
    """If DB says pending and sidecar finished, promote last-run.json into AcmeSettings."""
    row = ensure_acme_settings(db)
    last = read_acme_last_run(settings)
    if not last:
        return False
    finished = str(last.get("finished_at") or "").strip()
    status = str(last.get("status") or "ok").strip() or "ok"
    message = str(last.get("message") or "").strip()
    if not finished:
        return False

    # Only overwrite when pending, or when sidecar finished after our pending stamp.
    prev_status = (row.last_reconcile_status or "").strip()
    prev_at = row.last_reconcile_at
    try:
        finished_dt = datetime.fromisoformat(finished.replace("Z", "+00:00"))
    except ValueError:
        finished_dt = utcnow()

    if prev_status == "pending":
        should = True
    elif prev_at is None:
        should = True
    else:
        prev = prev_at if prev_at.tzinfo else prev_at.replace(tzinfo=timezone.utc)
        should = finished_dt > prev

    if not should:
        return False

    if sidecar_running(settings) and prev_status == "pending":
        # Still running — keep pending, but refresh message from partial progress via logs UI
        return False

    row.last_reconcile_at = finished_dt
    row.last_reconcile_status = status if status in ("ok", "error", "skipped", "pending") else "ok"
    row.last_reconcile_message = message[:2000] if message else row.last_reconcile_message
    row.updated_by = actor
    db.commit()
    return True


def _domain_to_dict(d: AcmeDomainStatus) -> dict[str, Any]:
    payload = asdict(d)
    for key in ("not_before", "not_after"):
        val = payload.get(key)
        if isinstance(val, datetime):
            payload[key] = val.isoformat()
    return payload


def build_acme_live_status(db: Session, settings: Settings) -> dict[str, Any]:
    """JSON payload for Admin ACME live panel (poll every few seconds)."""
    sync_reconcile_from_sidecar(db, settings)
    cfg = get_acme_config(db)
    domains = list_domain_statuses(db, settings)
    log_info = read_acme_reconcile_log(settings)
    last = read_acme_last_run(settings)
    running = sidecar_running(settings)
    pending_file = (certs_dir(settings) / ".reconcile_request").is_file()
    counts = {
        "total": len(domains),
        "ok": sum(1 for d in domains if d.status == "ok"),
        "renew_soon": sum(1 for d in domains if d.status == "renew_soon"),
        "missing": sum(1 for d in domains if d.status in ("missing", "placeholder", "expired")),
    }
    return {
        "enabled": cfg.enabled,
        "cf_token_configured": cfg.cf_token_configured,
        "dns_api": cfg.dns_api,
        "acme_ca": cfg.acme_ca,
        "last_reconcile_at": cfg.last_reconcile_at.isoformat() if cfg.last_reconcile_at else None,
        "last_reconcile_status": cfg.last_reconcile_status,
        "last_reconcile_message": cfg.last_reconcile_message,
        "sidecar_running": running,
        "reconcile_request_pending": pending_file,
        "poll_hint_seconds": 3 if (running or pending_file or cfg.last_reconcile_status == "pending") else 15,
        "counts": counts,
        "domains": [_domain_to_dict(d) for d in domains],
        "log": log_info,
        "last_run": last,
        "dns01_hint": (
            "DNS-01 Cloudflare : acme.sh crée et supprime automatiquement les TXT "
            "_acme-challenge.<fqdn> via l'API (token Zone.DNS Edit). "
            "Aucun record DNS manuel n'est requis — seuls les A/AAAA/CNAME publics "
            "vers le bastion restent à gérer hors ACME."
        ),
    }