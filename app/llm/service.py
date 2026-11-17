"""Portal-facing entry points for the optional LLM assistant.

Everything here degrades to "no assistant": callers get ``None`` and keep
their current behaviour. Enabled only when env ``LLM_ENABLED`` *and* the
admin toggle ``PortalSettings.llm_enabled`` are both on.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.audit import log_action
from app.llm.breaker import CLOSED
from app.llm.client import LlmCallResult, ProbeResult, get_llm_client
from app.models import PortalSettings
from app.portal_settings_service import ensure_portal_settings
from app.sso_settings import Settings, get_settings

logger = logging.getLogger(__name__)

_ACTOR = "system:llm"

STATE_DISABLED = "disabled"
STATE_AVAILABLE = "available"
STATE_UNAVAILABLE = "unavailable"
STATE_UNKNOWN = "unknown"  # enabled, no successful call or probe yet


def _admin_toggle(db: Session | None) -> bool:
    """Read PortalSettings.llm_enabled without ever raising."""
    try:
        if db is not None:
            row = db.get(PortalSettings, 1)
            return bool(getattr(row, "llm_enabled", False))
        from app.database import SessionLocal

        own = SessionLocal()
        try:
            row = own.get(PortalSettings, 1)
            return bool(getattr(row, "llm_enabled", False))
        finally:
            own.close()
    except Exception:
        logger.debug("llm toggle read failed", exc_info=True)
        return False


def llm_enabled(settings: Settings | None = None, db: Session | None = None) -> bool:
    settings = settings or get_settings()
    if not getattr(settings, "llm_enabled", False):
        return False  # env kill switch: no DB read, no network
    return _admin_toggle(db)


def _audit_call(db: Session | None, actor: str, result: LlmCallResult) -> None:
    if not result.network:
        return  # nothing left the process (disabled / busy / breaker open)
    action = "llm.call" if result.outcome == "ok" else "llm.call_failed"
    try:
        if db is not None:
            log_action(db, actor, action, target=f"llm:{result.task}",
                       details=result.audit_details(), forward_to_siem=False)
            return
        from app.database import SessionLocal

        own = SessionLocal()
        try:
            log_action(own, actor, action, target=f"llm:{result.task}",
                       details=result.audit_details(), forward_to_siem=False)
        finally:
            own.close()
    except Exception:
        logger.debug("llm audit failed", exc_info=True)


async def run_task(
    task: str,
    *,
    instructions: str,
    data: Any,
    schema: dict[str, Any],
    db: Session | None = None,
    settings: Settings | None = None,
    actor: str = _ACTOR,
    think: bool = False,
) -> LlmCallResult | None:
    """Like :func:`generate_json` but returns the full call result (model, hash).

    ``None`` when the assistant is disabled. Never raises.
    """
    try:
        settings = settings or get_settings()
        if not llm_enabled(settings, db):
            return None
        client = get_llm_client(settings)
        result = await client.generate_json(
            task=task, instructions=instructions, data=data, schema=schema, think=think
        )
        _audit_call(db, actor, result)
        return result
    except Exception:
        logger.warning("llm task %s failed unexpectedly", task, exc_info=True)
        return None


async def generate_json(
    task: str,
    *,
    instructions: str,
    data: Any,
    schema: dict[str, Any],
    db: Session | None = None,
    settings: Settings | None = None,
    actor: str = _ACTOR,
    think: bool = False,
) -> dict[str, Any] | None:
    """Ask the local model for a schema-constrained JSON answer.

    ``data`` is untrusted (logs, user agents, app names…): it is redacted,
    size-capped and fenced as data. Returns ``None`` whenever the assistant
    is disabled or unavailable, or the answer is invalid. Never raises.
    """
    result = await run_task(
        task, instructions=instructions, data=data, schema=schema,
        db=db, settings=settings, actor=actor, think=think,
    )
    if result is None or result.outcome != "ok":
        return None
    return result.value


async def probe_llm(
    settings: Settings,
    db: Session,
    *,
    actor: str,
    ip_address: str | None = None,
) -> ProbeResult:
    """Admin "test connection": light /api/tags call, audited. Never raises."""
    if not getattr(settings, "llm_enabled", False):
        return ProbeResult(ok=False, error="LLM_ENABLED=false (variable d'environnement)")
    try:
        result = await get_llm_client(settings).probe()
    except Exception as exc:  # noqa: BLE001
        result = ProbeResult(ok=False, error=type(exc).__name__)
    log_action(
        db,
        actor,
        "llm.probe",
        target="llm:ollama",
        details={
            "ok": result.ok,
            "model": settings.llm_model,
            "model_present": result.model_present,
            "duration_ms": result.duration_ms,
            "error": (result.error or "")[:300] or None,
        },
        ip_address=ip_address,
    )
    return result


def update_llm_settings(
    db: Session,
    settings: Settings,
    *,
    actor: str,
    enabled: bool,
    ip_address: str | None = None,
) -> PortalSettings:
    row = ensure_portal_settings(db, settings)
    row.llm_enabled = bool(enabled)
    db.commit()
    log_action(
        db,
        actor,
        "portal_settings.llm_assistant",
        target="portal_settings:llm",
        details={"enabled": bool(enabled), "env_enabled": bool(settings.llm_enabled)},
        ip_address=ip_address,
    )
    return row


def llm_public_status(settings: Settings, row: PortalSettings | None) -> dict[str, Any]:
    """Status for the admin badge. Pure in-memory: no network, no blocking."""
    env_on = bool(getattr(settings, "llm_enabled", False))
    admin_on = bool(getattr(row, "llm_enabled", False))
    out: dict[str, Any] = {
        "env_enabled": env_on,
        "admin_enabled": admin_on,
        "model": getattr(settings, "llm_model", ""),
        "url": getattr(settings, "ollama_url", ""),
        "state": STATE_DISABLED,
        "breaker": CLOSED,
        "last_error": None,
        "last_success": "",
    }
    if not (env_on and admin_on):
        return out
    client = get_llm_client(settings)
    breaker_state = client.state()
    out["breaker"] = breaker_state
    out["last_error"] = client.breaker.last_error
    if client.last_success_at:
        out["last_success"] = datetime.fromtimestamp(
            client.last_success_at, tz=UTC
        ).strftime("%Y-%m-%d %H:%M UTC")
    if breaker_state != CLOSED:
        out["state"] = STATE_UNAVAILABLE
    elif client.last_success_at or (client.last_probe and client.last_probe.ok):
        out["state"] = STATE_AVAILABLE
    elif client.breaker.last_error:
        out["state"] = STATE_UNAVAILABLE
    else:
        out["state"] = STATE_UNKNOWN
    return out
