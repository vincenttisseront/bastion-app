"""Keycloak groups sync for one realm, with a usable trace of every failure.

Both sync routes (``/admin/realms/{id}/sync`` and ``/admin/rbac/groups/sync/{id}``)
go through :func:`run_groups_sync`, so a failure always lands in:

- the application log (container ``bastion-app``): one line with the event
  code, realm, service-account client, Keycloak URL, HTTP status and detected
  cause (for example ``missing_admin_api_scope``);
- the audit trail, action ``rbac.groups.sync_failed`` (BST-RBAC-3001): shown in
  Admin → Logs and forwarded to the SIEM like any audit entry;
- ``RealmConfig.last_groups_sync_status/error``: the Sync ✗ on /admin/realms,
  dated from that audit entry (:func:`last_sync_failures`).

Nothing here logs a token or a secret.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.audit import log_action
from app.audit.event_catalog import format_log_line, resolve_event
from app.models import AuditLog, RealmConfig
from app.rbac.keycloak_admin import KeycloakAdminError, sync_keycloak_groups
from app.rbac.users_stats_service import clear_user_stats_cache
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

SYNC_OK_ACTION = "rbac.groups.sync"
SYNC_FAILED_ACTION = "rbac.groups.sync_failed"
SERVER_ERROR_MESSAGE = "Erreur serveur pendant la synchronisation des groupes"
_RESULT_AUDIT_KEYS = (
    "status",
    "fetched",
    "imported",
    "updated",
    "orphaned",
    "skipped",
    "members_refreshed",
    "members_total",
    "members_failed",
    "members_error",
)


@dataclass
class GroupsSyncOutcome:
    ok: bool
    result: dict[str, Any] = field(default_factory=dict)
    message: str = ""
    http_status: int = 200


async def run_groups_sync(
    db: Session,
    realm: RealmConfig,
    settings: Settings,
    *,
    actor: str,
    ip_address: str | None,
) -> GroupsSyncOutcome:
    """Run the sync, commit, and audit the result (success or failure)."""
    try:
        result = await sync_keycloak_groups(realm, db, settings)
        db.commit()
    except ValueError as exc:
        db.rollback()
        message = str(exc) or "Erreur de synchronisation"
        _record_failure(db, realm, exc, message, actor=actor, ip_address=ip_address)
        return GroupsSyncOutcome(ok=False, message=message, http_status=400)
    except Exception as exc:  # noqa: BLE001 — every failure must be traced
        db.rollback()
        _record_failure(
            db, realm, exc, SERVER_ERROR_MESSAGE, actor=actor, ip_address=ip_address
        )
        return GroupsSyncOutcome(ok=False, message=SERVER_ERROR_MESSAGE, http_status=500)

    clear_user_stats_cache()
    log_action(
        db,
        actor=actor,
        action=SYNC_OK_ACTION,
        target=realm.slug,
        details={k: result.get(k) for k in _RESULT_AUDIT_KEYS},
        ip_address=ip_address,
    )
    return GroupsSyncOutcome(ok=True, result=result)


def failure_facts(realm: RealmConfig, exc: BaseException) -> dict[str, Any]:
    """What logs and audit say about a failed sync (no token, no secret)."""
    client_id = realm.keycloak_admin_client_id
    if isinstance(exc, KeycloakAdminError):
        facts: dict[str, Any] = {
            "cause": exc.cause,
            "client_id": exc.client_id or client_id,
            "http_status": exc.status,
            "url": exc.url,
            "token_scope": exc.token_scope,
        }
    elif isinstance(exc, ValueError):
        facts = {"cause": "error", "client_id": client_id}
    else:
        facts = {"cause": "server_error", "client_id": client_id, "error_type": type(exc).__name__}
    return {k: v for k, v in facts.items() if v not in (None, "")}


def _log_fields(facts: dict[str, Any]) -> str:
    def fmt(value: Any) -> str:
        text = str(value)
        return f'"{text}"' if " " in text else text

    return " ".join(f"{key}={fmt(value)}" for key, value in facts.items())


def _record_failure(
    db: Session,
    realm: RealmConfig,
    exc: BaseException,
    message: str,
    *,
    actor: str,
    ip_address: str | None,
) -> None:
    facts = failure_facts(realm, exc)
    head = format_log_line(
        resolve_event(action=SYNC_FAILED_ACTION),
        actor=actor,
        ip=ip_address or "",
        result="error",
    )
    line = f"{head} realm={realm.slug} {_log_fields(facts)} reason={message}"
    if isinstance(exc, ValueError):
        logger.warning("%s", line)
    else:
        logger.error("%s", line, exc_info=exc)

    realm.last_groups_sync_status = "error"
    realm.last_groups_sync_error = message
    db.commit()
    log_action(
        db,
        actor=actor,
        action=SYNC_FAILED_ACTION,
        target=realm.slug,
        details={"reason": message, **facts},
        ip_address=ip_address,
    )


def last_sync_failures(db: Session, realms: Iterable[RealmConfig]) -> dict[str, AuditLog]:
    """Latest ``rbac.groups.sync_failed`` audit entry per realm currently in error."""
    slugs = [r.slug for r in realms if r.last_groups_sync_status == "error"]
    if not slugs:
        return {}
    latest_ids = [
        row_id
        for _slug, row_id in db.query(AuditLog.target, func.max(AuditLog.id))
        .filter(AuditLog.action == SYNC_FAILED_ACTION, AuditLog.target.in_(slugs))
        .group_by(AuditLog.target)
        .all()
    ]
    if not latest_ids:
        return {}
    rows = db.query(AuditLog).filter(AuditLog.id.in_(latest_ids)).all()
    return {row.target: row for row in rows}
