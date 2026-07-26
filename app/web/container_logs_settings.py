"""DB-backed ContainerLogsSettings singleton (admin-editable)."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import ContainerLogsSettings, utcnow

CONTAINER_LOGS_SETTINGS_ID = 1
DEFAULT_ALLOWED_CONTAINERS = ["bastion-app", "bastion-nginx", "nginx"]
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")


@dataclass(frozen=True)
class ContainerLogsConfig:
    enabled: bool
    proxy_url: str
    allowed_containers: list[str]
    tail_lines: int

    @property
    def active(self) -> bool:
        """Feature usable: admin-enabled and proxy URL set."""
        return bool(self.enabled and (self.proxy_url or "").strip())


def parse_allowed_containers_csv(value: str | None) -> list[str]:
    raw = (value or "").strip()
    if not raw:
        return []
    if raw.startswith("["):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return _normalize_names([str(x) for x in parsed])
        except json.JSONDecodeError:
            pass
    return _normalize_names(raw.split(","))


def _normalize_names(names: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for name in names:
        n = (name or "").strip()
        if not n or not _NAME_RE.match(n):
            continue
        key = n.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


def seed_values_from_environ(environ: dict[str, str] | None = None) -> dict:
    """
    Initial singleton values for migration / first ensure.

    If legacy DOCKER_LOGS_PROXY_URL is set, enable and adopt proxy + whitelist.
    Otherwise disabled with empty proxy and default suggested container names.
    """
    env = environ if environ is not None else os.environ
    proxy = (env.get("DOCKER_LOGS_PROXY_URL") or "").strip()
    wl_raw = (env.get("DOCKER_LOGS_WHITELIST") or "").strip()
    if wl_raw:
        allowed = parse_allowed_containers_csv(wl_raw)
    else:
        allowed = list(DEFAULT_ALLOWED_CONTAINERS)
    tail_raw = (env.get("DOCKER_LOGS_TAIL_LINES") or "").strip()
    try:
        tail = int(tail_raw) if tail_raw else 200
    except ValueError:
        tail = 200
    tail = max(1, min(tail, 5000))
    return {
        "enabled": bool(proxy),
        "proxy_url": proxy,
        "allowed_containers": allowed,
        "tail_lines": tail,
    }


def ensure_container_logs_settings(db: Session) -> ContainerLogsSettings:
    row = (
        db.query(ContainerLogsSettings)
        .filter_by(id=CONTAINER_LOGS_SETTINGS_ID)
        .first()
    )
    if row is not None:
        return row
    seed = seed_values_from_environ()
    row = ContainerLogsSettings(
        id=CONTAINER_LOGS_SETTINGS_ID,
        enabled=bool(seed["enabled"]),
        proxy_url=str(seed["proxy_url"] or ""),
        allowed_containers=list(seed["allowed_containers"] or []),
        tail_lines=int(seed["tail_lines"] or 200),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def get_container_logs_config(db: Session) -> ContainerLogsConfig:
    row = ensure_container_logs_settings(db)
    allowed = row.allowed_containers if isinstance(row.allowed_containers, list) else []
    return ContainerLogsConfig(
        enabled=bool(row.enabled),
        proxy_url=(row.proxy_url or "").strip(),
        allowed_containers=_normalize_names([str(x) for x in allowed]),
        tail_lines=max(1, min(int(row.tail_lines or 200), 5000)),
    )


def _audit_updated(
    db: Session,
    row: ContainerLogsSettings,
    *,
    actor: str,
    ip_address: str | None,
    details: dict,
) -> None:
    log_action(
        db,
        actor=actor,
        action="security.container_logs_settings.updated",
        target="container_logs_settings",
        details=details,
        ip_address=ip_address,
    )


def update_container_logs_settings(
    db: Session,
    *,
    enabled: bool,
    proxy_url: str,
    tail_lines: int = 200,
    actor: str,
    ip_address: str | None = None,
) -> ContainerLogsSettings:
    row = ensure_container_logs_settings(db)
    row.enabled = bool(enabled)
    row.proxy_url = (proxy_url or "").strip()
    row.tail_lines = max(1, min(int(tail_lines or 200), 5000))
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)
    _audit_updated(
        db,
        row,
        actor=actor,
        ip_address=ip_address,
        details={
            "enabled": row.enabled,
            "proxy_url": row.proxy_url,
            "tail_lines": row.tail_lines,
            "allowed_containers": list(row.allowed_containers or []),
            "op": "save",
        },
    )
    return row


def add_allowed_container(
    db: Session,
    name: str,
    *,
    actor: str,
    ip_address: str | None = None,
) -> ContainerLogsSettings:
    row = ensure_container_logs_settings(db)
    names = _normalize_names(
        [str(x) for x in (row.allowed_containers or [])] + [name]
    )
    if not _normalize_names([name]):
        raise ValueError("invalid container name")
    row.allowed_containers = names
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)
    _audit_updated(
        db,
        row,
        actor=actor,
        ip_address=ip_address,
        details={
            "op": "add_container",
            "container": _normalize_names([name])[0],
            "allowed_containers": list(row.allowed_containers or []),
        },
    )
    return row


def remove_allowed_container(
    db: Session,
    name: str,
    *,
    actor: str,
    ip_address: str | None = None,
) -> ContainerLogsSettings:
    row = ensure_container_logs_settings(db)
    key = (name or "").strip().casefold()
    current = [str(x) for x in (row.allowed_containers or [])]
    filtered = [n for n in current if n.casefold() != key]
    row.allowed_containers = _normalize_names(filtered)
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)
    _audit_updated(
        db,
        row,
        actor=actor,
        ip_address=ip_address,
        details={
            "op": "remove_container",
            "container": (name or "").strip(),
            "allowed_containers": list(row.allowed_containers or []),
        },
    )
    return row
