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

    @property
    def active(self) -> bool:
        if not self.enabled:
            return False
        if self.protocol == "syslog_tls":
            return bool(self.syslog_host.strip())
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


def get_siem_config(db: Session) -> SiemForwardingConfig:
    row = ensure_siem_settings(db)
    actions = row.filter_actions if isinstance(row.filter_actions, list) else []
    return SiemForwardingConfig(
        enabled=bool(row.enabled),
        protocol=(row.protocol or "webhook_https").strip(),
        syslog_host=(row.syslog_host or "").strip(),
        syslog_port=int(row.syslog_port or 6514),
        syslog_tls_verify=bool(row.syslog_tls_verify),
        webhook_url=(row.webhook_url or "").strip(),
        webhook_auth_type=(row.webhook_auth_type or "none").strip(),
        webhook_auth_configured=bool((row.webhook_auth_secret_encrypted or "").strip()),
        filter_mode=(row.filter_mode or "denylist").strip(),
        filter_actions=[str(a).strip() for a in actions if str(a).strip()],
        retry_max_queue_size=max(1, min(int(row.retry_max_queue_size or 5000), 100_000)),
        retry_max_age_minutes=max(1, min(int(row.retry_max_age_minutes or 1440), 60 * 24 * 30)),
        last_success_at=row.last_success_at,
    )


def action_passes_filter(config: SiemForwardingConfig, action: str) -> bool:
    act = (action or "").strip()
    if act.startswith("siem."):
        return False
    names = set(config.filter_actions)
    if config.filter_mode == "allowlist":
        return act in names if names else False
    # denylist (default): empty list → forward all (except siem.*)
    return act not in names


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

    row.enabled = bool(enabled)
    row.protocol = proto
    row.syslog_host = (syslog_host or "").strip()
    row.syslog_port = max(1, min(int(syslog_port or 6514), 65535))
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
        details={
            "enabled": row.enabled,
            "protocol": row.protocol,
            "syslog_host": row.syslog_host,
            "syslog_port": row.syslog_port,
            "syslog_tls_verify": row.syslog_tls_verify,
            "webhook_url": row.webhook_url,
            "webhook_auth_type": row.webhook_auth_type,
            "webhook_auth_configured": bool(row.webhook_auth_secret_encrypted),
            "filter_mode": row.filter_mode,
            "filter_actions": list(row.filter_actions or []),
            "retry_max_queue_size": row.retry_max_queue_size,
            "retry_max_age_minutes": row.retry_max_age_minutes,
        },
        ip_address=ip_address,
        forward_to_siem=False,
    )
    return row


def mark_siem_success(db: Session) -> None:
    row = ensure_siem_settings(db)
    row.last_success_at = utcnow()
    db.commit()


def public_status(db: Session) -> dict[str, Any]:
    from app.siem.outbox import queue_size

    cfg = get_siem_config(db)
    return {
        "enabled": cfg.enabled,
        "active": cfg.active,
        "protocol": cfg.protocol,
        "webhook_auth_configured": cfg.webhook_auth_configured,
        "last_success_at": cfg.last_success_at.isoformat() if cfg.last_success_at else None,
        "queue_size": queue_size(db),
        "filter_mode": cfg.filter_mode,
        "filter_actions": list(cfg.filter_actions),
    }
