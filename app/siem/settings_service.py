"""DB-backed SiemForwardingSettings singleton (admin-editable, disabled by default)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import SiemForwardingSettings, utcnow
from app.secret_crypto import decrypt_secret, encrypt_secret
from app.sso_settings import Settings

SIEM_SETTINGS_ID = 1
PROTOCOLS = frozenset({"syslog_tls", "webhook_https"})
AUTH_TYPES = frozenset({"none", "bearer", "basic"})
FILTER_MODES = frozenset({"allowlist", "denylist"})


@dataclass(frozen=True)
class SiemForwardingConfig:
    enabled: bool
    protocol: str
    syslog_host: str
    syslog_port: int
    syslog_tls_verify: bool
    webhook_url: str
    webhook_auth_type: str
    webhook_auth_configured: bool
    filter_mode: str
    filter_actions: list[str]
    retry_max_queue_size: int
    retry_max_age_minutes: int
    last_success_at: datetime | None
    syslog_ca_relative_path: str | None = None
    syslog_ca_valid: bool = False

    @property
    def active(self) -> bool:
        if not self.enabled:
            return False
        if self.protocol == "syslog_tls":
            # tls_verify=false is never effective; CA file must be valid.
            if not self.syslog_tls_verify:
                return False
            return bool(self.syslog_host.strip()) and self.syslog_ca_valid
        if self.protocol == "webhook_https":
            return self.webhook_url.startswith("https://")
        return False


def ensure_siem_settings(db: Session) -> SiemForwardingSettings:
    row = db.query(SiemForwardingSettings).filter_by(id=SIEM_SETTINGS_ID).first()
    if row is not None:
        return row
    row = SiemForwardingSettings(
        id=SIEM_SETTINGS_ID,
        enabled=False,
        protocol="webhook_https",
        syslog_host="",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="",
        webhook_auth_type="none",
        webhook_auth_secret_encrypted=None,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=5000,
        retry_max_age_minutes=1440,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def get_siem_config(
    db: Session, settings: Settings | None = None
) -> SiemForwardingConfig:
    from app.siem import syslog_ca as ca
    from app.sso_settings import get_settings as _get_settings

    row = ensure_siem_settings(db)
    actions = row.filter_actions if isinstance(row.filter_actions, list) else []
    rel = (getattr(row, "syslog_ca_relative_path", None) or "").strip() or None
    resolved_settings = settings or _get_settings()
    # Derive validity from the active file — never trust a DB boolean alone.
    ca_valid = bool(rel) and ca.is_active_ca_valid(
        resolved_settings, relative_path=rel
    )
    protocol = (row.protocol or "webhook_https").strip()
    # tls_verify=false is never effective for Syslog TCP+TLS.
    tls_verify = True if protocol == "syslog_tls" else bool(row.syslog_tls_verify)
    return SiemForwardingConfig(
        enabled=bool(row.enabled),
        protocol=protocol,
        syslog_host=(row.syslog_host or "").strip(),
        syslog_port=int(row.syslog_port or 6514),
        syslog_tls_verify=tls_verify,
        webhook_url=(row.webhook_url or "").strip(),
        webhook_auth_type=(row.webhook_auth_type or "none").strip(),
        webhook_auth_configured=bool((row.webhook_auth_secret_encrypted or "").strip()),
        filter_mode=(row.filter_mode or "denylist").strip(),
        filter_actions=[str(a).strip() for a in actions if str(a).strip()],
        retry_max_queue_size=max(1, min(int(row.retry_max_queue_size or 5000), 100_000)),
        retry_max_age_minutes=max(1, min(int(row.retry_max_age_minutes or 1440), 60 * 24 * 30)),
        last_success_at=row.last_success_at,
        syslog_ca_relative_path=rel,
        syslog_ca_valid=ca_valid,
    )


def action_passes_filter(config: SiemForwardingConfig, action: str) -> bool:
    """Backward-compatible wrapper — prefer ``event_passes_filter``."""
    return event_passes_filter(config, action=action)


def _severity_rank_name(name: str) -> int | None:
    from app.audit.event_catalog import SEVERITY_RANK, Severity

    try:
        return SEVERITY_RANK[Severity(name.upper())]
    except (KeyError, ValueError):
        return None


def _criterion_severity_matches(crit: str, sev: str) -> bool:
    if not crit.upper().startswith("SEVERITY>="):
        return False
    min_name = crit.split("=", 1)[-1].strip().upper()
    min_rank = _severity_rank_name(min_name)
    cur_rank = _severity_rank_name(sev) if sev else None
    if min_rank is None or cur_rank is None:
        return False
    return cur_rank >= min_rank


def _criterion_bst_matches(crit: str, *, code: str, domain: str) -> bool | None:
    """Return True/False for BST criteria, or None if criterion is not BST-shaped."""
    upper = crit.upper()
    if not upper.startswith("BST-"):
        return None
    if crit.endswith("*"):
        prefix = crit[:-1].upper()
        if code.startswith(prefix):
            return True
        parts = prefix.rstrip("-").split("-")
        return bool(len(parts) >= 2 and domain == parts[1])
    return upper == code


def _criterion_matches(
    criterion: str,
    *,
    action: str,
    event_code: str,
    catalog_severity: str,
    domain: str,
) -> bool:
    """Match one filter criterion: exact action, BST-WAF-*, or severity>=ERROR."""
    crit = (criterion or "").strip()
    if not crit:
        return False
    act = (action or "").strip()
    code = (event_code or "").strip().upper()
    sev = (catalog_severity or "").strip().upper()
    dom = (domain or "").strip().upper()

    if _criterion_severity_matches(crit, sev):
        return True
    if crit.upper().startswith("SEVERITY>="):
        return False

    bst = _criterion_bst_matches(crit, code=code, domain=dom)
    if bst is not None:
        return bst

    return crit == act


def event_passes_filter(
    config: SiemForwardingConfig,
    *,
    action: str,
    event_code: str | None = None,
    catalog_severity: str | None = None,
    domain: str | None = None,
    entry: dict | None = None,
) -> bool:
    """Allow/deny using action names, event codes, BST-DOMAIN-* globs, severity>=X."""
    act = (action or "").strip()
    if act.startswith("siem."):
        return False
    act, code, sev, dom = _filter_identity(
        action=act,
        event_code=event_code,
        catalog_severity=catalog_severity,
        domain=domain,
        entry=entry,
    )
    criteria = [str(a).strip() for a in config.filter_actions if str(a).strip()]
    if config.filter_mode == "allowlist":
        if not criteria:
            return False
        return any(
            _criterion_matches(
                c, action=act, event_code=code, catalog_severity=sev, domain=dom
            )
            for c in criteria
        )
    # denylist (default): empty → forward all (except siem.*)
    return not any(
        _criterion_matches(
            c, action=act, event_code=code, catalog_severity=sev, domain=dom
        )
        for c in criteria
    )


def _filter_identity(
    *,
    action: str,
    event_code: str | None,
    catalog_severity: str | None,
    domain: str | None,
    entry: dict | None,
) -> tuple[str, str, str, str]:
    act = action
    if entry:
        event_code = event_code or entry.get("event_code")
        catalog_severity = catalog_severity or entry.get("catalog_severity")
        domain = domain or entry.get("domain")
        act = act or str(entry.get("action") or "")
    code = (event_code or "").strip()
    sev = (catalog_severity or "").strip()
    dom = (domain or "").strip()
    if not code and not sev:
        from app.audit.event_catalog import resolve_event

        ev = resolve_event(action=act)
        return act, ev.code, ev.severity.value, ev.domain
    return act, code, sev, dom


def resolve_webhook_secret(db: Session, settings: Settings) -> str | None:
    row = ensure_siem_settings(db)
    cipher = (row.webhook_auth_secret_encrypted or "").strip()
    if not cipher:
        return None
    try:
        return decrypt_secret(cipher, settings)
    except Exception:
        return None


def update_siem_settings(
    db: Session,
    settings: Settings,
    *,
    enabled: bool,
    protocol: str,
    syslog_host: str,
    syslog_port: int,
    syslog_tls_verify: bool,
    webhook_url: str,
    webhook_auth_type: str,
    webhook_auth_secret: str | None,
    clear_webhook_secret: bool,
    filter_mode: str,
    filter_actions: list[str],
    retry_max_queue_size: int,
    retry_max_age_minutes: int,
    actor: str,
    ip_address: str | None = None,
) -> SiemForwardingSettings:
    row = ensure_siem_settings(db)
    proto, auth, mode, url = _validated_siem_update_fields(
        protocol=protocol,
        webhook_auth_type=webhook_auth_type,
        filter_mode=filter_mode,
        webhook_url=webhook_url,
    )

    row.enabled = bool(enabled)
    row.protocol = proto
    row.syslog_host = (syslog_host or "").strip()
    row.syslog_port = max(1, min(int(syslog_port or 6514), 65535))
    # Never persist tls_verify=false for Syslog TCP+TLS.
    if proto == "syslog_tls":
        row.syslog_tls_verify = True
    else:
        row.syslog_tls_verify = bool(syslog_tls_verify)
    row.webhook_url = url
    row.webhook_auth_type = auth
    row.filter_mode = mode
    row.filter_actions = [a.strip() for a in filter_actions if a and str(a).strip()]
    row.retry_max_queue_size = max(1, min(int(retry_max_queue_size or 5000), 100_000))
    row.retry_max_age_minutes = max(1, min(int(retry_max_age_minutes or 1440), 60 * 24 * 30))
    row.updated_at = utcnow()
    row.updated_by = actor

    if clear_webhook_secret:
        row.webhook_auth_secret_encrypted = None
    elif webhook_auth_secret and webhook_auth_secret.strip():
        row.webhook_auth_secret_encrypted = encrypt_secret(
            webhook_auth_secret.strip(), settings
        )

    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="security.siem_forwarding_settings.updated",
        target="siem_forwarding_settings",
        details=_siem_settings_audit_details(row),
        ip_address=ip_address,
        forward_to_siem=False,
    )
    return row


def _validated_siem_update_fields(
    *,
    protocol: str,
    webhook_auth_type: str,
    filter_mode: str,
    webhook_url: str,
) -> tuple[str, str, str, str]:
    proto = (protocol or "").strip()
    if proto not in PROTOCOLS:
        raise ValueError("invalid protocol")
    auth = (webhook_auth_type or "none").strip()
    if auth not in AUTH_TYPES:
        raise ValueError("invalid webhook_auth_type")
    mode = (filter_mode or "denylist").strip()
    if mode not in FILTER_MODES:
        raise ValueError("invalid filter_mode")
    url = (webhook_url or "").strip()
    if url and not url.startswith("https://"):
        raise ValueError("webhook_url must be https://")
    return proto, auth, mode, url


def _siem_settings_audit_details(row: SiemForwardingSettings) -> dict[str, Any]:
    return {
        "enabled": row.enabled,
        "protocol": row.protocol,
        "syslog_host": row.syslog_host,
        "syslog_port": row.syslog_port,
        "syslog_tls_verify": row.syslog_tls_verify,
        "syslog_ca_relative_path": getattr(row, "syslog_ca_relative_path", None),
        "syslog_ca_fingerprint_sha256": getattr(
            row, "syslog_ca_fingerprint_sha256", None
        ),
        "webhook_url": row.webhook_url,
        "webhook_auth_type": row.webhook_auth_type,
        "webhook_auth_configured": bool(row.webhook_auth_secret_encrypted),
        "filter_mode": row.filter_mode,
        "filter_actions": list(row.filter_actions or []),
        "retry_max_queue_size": row.retry_max_queue_size,
        "retry_max_age_minutes": row.retry_max_age_minutes,
    }


def mark_siem_success(db: Session) -> None:
    row = ensure_siem_settings(db)
    row.last_success_at = utcnow()
    db.commit()


def public_status(db: Session) -> dict[str, Any]:
    from app.db.hot_store import hot_read
    from app.siem import outbox

    cfg = get_siem_config(db)
    pending = hot_read(
        lambda: outbox.queue_size(db),
        default=None,
        what="SIEM outbox size",
        db=db,
    )
    return {
        "enabled": cfg.enabled,
        "active": cfg.active,
        "protocol": cfg.protocol,
        "webhook_auth_configured": cfg.webhook_auth_configured,
        "last_success_at": cfg.last_success_at.isoformat() if cfg.last_success_at else None,
        "queue_size": pending,
        "filter_mode": cfg.filter_mode,
        "filter_actions": list(cfg.filter_actions),
    }
