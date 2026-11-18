"""Portal-facing entry points for the optional LLM assistant.

Everything here degrades to "no assistant": callers get ``None`` and keep
their current behaviour.

Enablement: the admin toggle ``PortalSettings.llm_enabled`` (off by default)
plus a connection configured in Admin → Configuration → Assistant IA (local
or remote Ollama, optional Bearer token, optional self-signed TLS). The env
``LLM_ENABLED=false`` is an ops kill switch that short-circuits everything
before any DB read or socket.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.orm import Session

from app.audit import log_action
from app.llm.breaker import CLOSED
from app.llm.client import (
    LlmCallResult,
    LlmClient,
    LlmConfig,
    ProbeResult,
    client_for,
    normalize_num_ctx,
)
from app.models import PortalSettings, utcnow
from app.portal_settings_service import ensure_portal_settings
from app.sso_settings import Settings, get_settings

logger = logging.getLogger(__name__)

_ACTOR = "system:llm"

TIMEOUT_MIN_S = 10
TIMEOUT_MAX_S = 300
NUM_CTX_CHOICES = (0, 4096, 8192, 16384, 32768)  # 0 = auto (server's loaded context)

STATE_DISABLED = "disabled"
STATE_AVAILABLE = "available"
STATE_UNAVAILABLE = "unavailable"
STATE_UNKNOWN = "unknown"  # enabled, no successful call or probe yet


# ── enablement / configuration ─────────────────────────────────────────────


def env_allows(settings: Settings | None) -> bool:
    """False only when ops set LLM_ENABLED=false (kill switch). Unset = allowed."""
    return getattr(settings, "llm_enabled", None) is not False


def _read_row(db: Session | None) -> PortalSettings | None:
    """PortalSettings singleton without ever raising (own session if needed)."""
    try:
        if db is not None:
            return db.get(PortalSettings, 1)
        from app.database import SessionLocal

        own = SessionLocal()
        try:
            row = own.get(PortalSettings, 1)
            if row is not None:
                own.expunge(row)
            return row
        finally:
            own.close()
    except Exception:
        logger.debug("llm settings read failed", exc_info=True)
        return None


def llm_enabled(settings: Settings | None = None, db: Session | None = None) -> bool:
    settings = settings or get_settings()
    if not env_allows(settings):
        return False  # kill switch: no DB read, no network
    row = _read_row(db)
    return bool(getattr(row, "llm_enabled", False))


def companion_enabled(settings: Settings | None = None, db: Session | None = None) -> bool:
    """End-user companion: needs the assistant on AND its own admin toggle (off by default).

    Same kill switch as everything else: ``LLM_ENABLED=false`` returns before any DB read.
    """
    settings = settings or get_settings()
    if not env_allows(settings):
        return False
    row = _read_row(db)
    return bool(getattr(row, "llm_enabled", False) and getattr(row, "llm_companion_enabled", False))


def auto_response_enabled(settings: Settings | None = None, db: Session | None = None) -> bool:
    """Autonomous response (alert / revoke own sessions / temporary ban): its own admin toggle."""
    settings = settings or get_settings()
    if not env_allows(settings):
        return False
    row = _read_row(db)
    return bool(
        getattr(row, "llm_enabled", False) and getattr(row, "llm_auto_response_enabled", False)
    )


def effective_config(settings: Settings, row: PortalSettings | None) -> LlmConfig:
    """Env defaults overridden by the admin-configured connection."""
    config = LlmConfig.from_settings(settings)
    if row is None:
        return config
    token = ""
    if getattr(row, "llm_api_token_encrypted", None):
        try:
            from app.secret_crypto import decrypt_secret

            token = decrypt_secret(row.llm_api_token_encrypted, settings) or ""
        except Exception:  # noqa: BLE001 — key rotated / corrupt: call without token
            logger.warning("llm api token could not be decrypted")
    return replace(
        config,
        url=(row.llm_base_url or config.url).rstrip("/"),
        model=row.llm_model or (config.model if not row.llm_base_url else ""),
        api_token=token,
        verify_tls=bool(row.llm_tls_verify) if row.llm_tls_verify is not None else True,
        timeout_s=(
            float(max(TIMEOUT_MIN_S, min(TIMEOUT_MAX_S, row.llm_timeout_s)))
            if getattr(row, "llm_timeout_s", None) else config.timeout_s
        ),
        num_ctx=(
            normalize_num_ctx(row.llm_num_ctx)
            if getattr(row, "llm_num_ctx", None) is not None else config.num_ctx
        ),
    )


def get_llm_client(settings: Settings, db: Session | None = None) -> LlmClient:
    return client_for(effective_config(settings, _read_row(db)))


def validate_base_url(raw: str) -> str:
    """Normalise an Ollama base URL (IP or FQDN, optional port and path prefix)."""
    value = (raw or "").strip()
    if not value:
        raise ValueError("Adresse du serveur Ollama requise.")
    if "://" not in value:
        # NOSONAR python:S5332 — bare "host:port" means a local Ollama, which serves
        # plain HTTP by default; the admin can type https:// (TLS check optional) and
        # the panel warns when a token would travel over http://.
        value = "http://" + value  # NOSONAR
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise ValueError("L'adresse doit commencer par http:// ou https://.")
    if not parts.hostname:
        raise ValueError("Adresse invalide : hôte manquant.")
    if parts.username or parts.password:
        raise ValueError("Pas d'identifiants dans l'URL : utilisez le champ jeton.")
    if parts.query or parts.fragment:
        raise ValueError("L'adresse ne doit contenir ni paramètres (?) ni ancre (#).")
    try:
        _ = parts.port
    except ValueError as exc:
        raise ValueError("Port invalide.") from exc
    path = parts.path.rstrip("/")
    path = path.removesuffix("/api")  # people paste .../api: keep the base
    if ".." in path or "//" in path or "\\" in path:
        raise ValueError("Chemin invalide dans l'adresse.")
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


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


# ── calls ──────────────────────────────────────────────────────────────────


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
    audience: str = "admin",
) -> LlmCallResult | None:
    """Like :func:`generate_json` but returns the full call result (model, hash).

    ``None`` when the assistant is disabled. Never raises.
    """
    try:
        settings = settings or get_settings()
        if not llm_enabled(settings, db):
            return None
        client = get_llm_client(settings, db)
        if not client.config.model:
            return None  # connection tested but no model chosen yet
        result = await client.generate_json(
            task=task, instructions=instructions, data=data, schema=schema,
            think=think, audience=audience,
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
    """Ask the model for a schema-constrained JSON answer.

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
    """Admin "test connection": ``GET /api/tags`` with the saved connection.

    Works before the assistant is enabled (that is how models are discovered).
    Stores the model list and the outcome on PortalSettings. Never raises.
    """
    if not env_allows(settings):
        return ProbeResult(ok=False, error="LLM_ENABLED=false (variable d'environnement)")
    row = ensure_portal_settings(db, settings)
    try:
        result = await client_for(effective_config(settings, row)).probe(include_loaded=True)
    except Exception as exc:  # noqa: BLE001
        result = ProbeResult(ok=False, error=type(exc).__name__)
    row.llm_last_probe_at = utcnow()
    row.llm_last_probe_ok = bool(result.reachable)
    row.llm_last_probe_error = None if result.reachable else (result.error or "")[:500]
    if result.reachable:
        row.llm_models_json = list(result.models)
        row.llm_server_info = {"loaded": list(result.loaded)}
    db.commit()
    log_action(
        db,
        actor,
        "llm.probe",
        target="llm:ollama",
        details={
            "reachable": result.reachable,
            "url": row.llm_base_url or settings.ollama_url,
            "tls_verify": bool(row.llm_tls_verify),
            "token": bool(row.llm_api_token_encrypted),
            "models": len(result.models),
            "model": row.llm_model,
            "model_present": result.model_present,
            "duration_ms": result.duration_ms,
            "error": (result.error or "")[:300] or None,
        },
        ip_address=ip_address,
    )
    return result


def save_llm_connection(
    db: Session,
    settings: Settings,
    *,
    actor: str,
    base_url: str,
    api_token: str = "",
    clear_token: bool = False,
    tls_verify: bool = True,
    ip_address: str | None = None,
) -> PortalSettings:
    url = validate_base_url(base_url)
    row = ensure_portal_settings(db, settings)
    changed_target = url != (row.llm_base_url or "")
    row.llm_base_url = url
    row.llm_tls_verify = bool(tls_verify)
    token = (api_token or "").strip()
    if clear_token:
        row.llm_api_token_encrypted = None
    elif token:
        from app.secret_crypto import encrypt_secret

        row.llm_api_token_encrypted = encrypt_secret(token, settings)
    if changed_target:
        # Another server: the old model list / choice no longer applies.
        row.llm_models_json = None
        row.llm_model = None
        row.llm_last_probe_ok = None
    db.commit()
    log_action(
        db,
        actor,
        "portal_settings.llm_connection",
        target="portal_settings:llm",
        details={
            "url": url,
            "tls_verify": bool(tls_verify),
            "token": bool(row.llm_api_token_encrypted),
            "token_changed": bool(token) or clear_token,
        },
        ip_address=ip_address,
    )
    return row


def update_llm_settings(
    db: Session,
    settings: Settings,
    *,
    actor: str,
    enabled: bool,
    model: str | None = None,
    waf_auto: bool | None = None,
    companion: bool | None = None,
    auto_response: bool | None = None,
    timeout_s: int | None = None,
    num_ctx: int | None = None,
    ip_address: str | None = None,
) -> PortalSettings:
    row = ensure_portal_settings(db, settings)
    if timeout_s is not None:
        if not TIMEOUT_MIN_S <= int(timeout_s) <= TIMEOUT_MAX_S:
            raise ValueError(f"Délai entre {TIMEOUT_MIN_S} et {TIMEOUT_MAX_S} secondes.")
        row.llm_timeout_s = int(timeout_s)
    if num_ctx is not None:
        if int(num_ctx) not in NUM_CTX_CHOICES:
            raise ValueError("Fenêtre de contexte non prise en charge.")
        row.llm_num_ctx = int(num_ctx)
    if model is not None:
        model = model.strip()
        known = list(row.llm_models_json or [])
        if model and known and model not in known:
            raise ValueError("Modèle inconnu de ce serveur : relancez le test de connexion.")
        row.llm_model = model or None
    if enabled and not (row.llm_model or (not row.llm_base_url and settings.llm_model)):
        raise ValueError("Testez la connexion puis choisissez un modèle avant d'activer l'assistant.")
    row.llm_enabled = bool(enabled)
    if waf_auto is not None:
        row.llm_waf_auto_enabled = bool(waf_auto)
    if companion is not None:
        row.llm_companion_enabled = bool(companion)
    if auto_response is not None:
        row.llm_auto_response_enabled = bool(auto_response)
    db.commit()
    log_action(
        db,
        actor,
        "portal_settings.llm_assistant",
        target="portal_settings:llm",
        details={
            "enabled": bool(enabled),
            "model": row.llm_model,
            "waf_auto": bool(row.llm_waf_auto_enabled),
            "companion": bool(row.llm_companion_enabled),
            "auto_response": bool(row.llm_auto_response_enabled),
            "timeout_s": row.llm_timeout_s,
            "num_ctx": row.llm_num_ctx,
            "env_kill_switch": not env_allows(settings),
        },
        ip_address=ip_address,
    )
    return row


# ── status (admin badge / panel) ───────────────────────────────────────────


def _fmt(dt: Any) -> str:
    try:
        return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else ""
    except (AttributeError, ValueError):
        return str(dt or "")


def llm_public_status(settings: Settings, row: PortalSettings | None) -> dict[str, Any]:
    """Status for the admin badge and panel. In-memory only: no network."""
    config = effective_config(settings, row)
    env_on = env_allows(settings)
    admin_on = bool(getattr(row, "llm_enabled", False))
    models = list(getattr(row, "llm_models_json", None) or [])
    out: dict[str, Any] = {
        "env_enabled": env_on,
        "admin_enabled": admin_on,
        "url": config.url,
        "url_configured": bool(getattr(row, "llm_base_url", None)),
        "token_configured": bool(getattr(row, "llm_api_token_encrypted", None)),
        "tls_verify": config.verify_tls,
        "plain_http_with_token": config.url.startswith("http://") and bool(config.api_token),
        "model": config.model,
        "models": models,
        "model_missing": bool(config.model and models and config.model not in models),
        "waf_auto": bool(getattr(row, "llm_waf_auto_enabled", True)),
        "timeout_s": int(config.timeout_s),
        "num_ctx": config.num_ctx,
        "num_ctx_choices": NUM_CTX_CHOICES,
        "loaded_models": list(((getattr(row, "llm_server_info", None) or {}).get("loaded")) or []),
        "companion": bool(getattr(row, "llm_companion_enabled", False)),
        "auto_response": bool(getattr(row, "llm_auto_response_enabled", False)),
        "last_probe": _fmt(getattr(row, "llm_last_probe_at", None)),
        "last_probe_ok": getattr(row, "llm_last_probe_ok", None),
        "last_probe_error": getattr(row, "llm_last_probe_error", None),
        "state": STATE_DISABLED,
        "breaker": CLOSED,
        "last_error": None,
        "last_success": "",
    }
    if not (env_on and admin_on):
        return out
    client = client_for(config)
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
    elif out["last_probe_ok"] and not out["model_missing"]:
        out["state"] = STATE_AVAILABLE
    else:
        out["state"] = STATE_UNKNOWN
    return out
