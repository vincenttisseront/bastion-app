"""Portal runtime HMAC secrets stored in ``portal_settings`` (Fernet).

Source of truth is SQLite — not ``.env``. Optional env vars remain for pytest /
emergency override only. Idempotent ensure is safe from Alembic migrate, Ansible,
or app boot.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import utcnow
from app.portal_settings_service import ensure_portal_settings
from app.secret_crypto import decrypt_secret, encrypt_secret, generate_cookie_secret
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

AUDIT_ENSURED = "portal_runtime_secrets_ensured"

# Process cache after ensure/resolve (avoids DB hit on every hop seal / request without db).
_CACHED_HOP_SECRET: str | None = None
_CACHED_BREAKGLASS_SECRET: str | None = None
_CACHED_OIDC_SESSION_JWT_SECRET: str | None = None


def reset_runtime_secrets_cache_for_tests() -> None:
    global _CACHED_HOP_SECRET, _CACHED_BREAKGLASS_SECRET, _CACHED_OIDC_SESSION_JWT_SECRET
    _CACHED_HOP_SECRET = None
    _CACHED_BREAKGLASS_SECRET = None
    _CACHED_OIDC_SESSION_JWT_SECRET = None


def cache_session_hop_secret(plain: str) -> None:
    global _CACHED_HOP_SECRET
    _CACHED_HOP_SECRET = (plain or "").strip() or None


def cache_breakglass_secret(plain: str) -> None:
    global _CACHED_BREAKGLASS_SECRET
    _CACHED_BREAKGLASS_SECRET = (plain or "").strip() or None


def cache_oidc_session_jwt_secret(plain: str) -> None:
    global _CACHED_OIDC_SESSION_JWT_SECRET
    _CACHED_OIDC_SESSION_JWT_SECRET = (plain or "").strip() or None


def get_cached_breakglass_secret() -> str | None:
    return _CACHED_BREAKGLASS_SECRET


def get_cached_oidc_session_jwt_secret() -> str | None:
    return _CACHED_OIDC_SESSION_JWT_SECRET


def get_db_session_hop_secret(db: Session | None, settings: Settings) -> str | None:
    if db is None:
        return None
    row = ensure_portal_settings(db, settings)
    raw = (getattr(row, "session_hop_secret_encrypted", None) or "").strip()
    if not raw:
        return None
    try:
        plain = decrypt_secret(raw, settings).strip()
    except ValueError:
        logger.warning("failed to decrypt portal_settings.session_hop_secret_encrypted")
        return None
    return plain or None


def get_db_oidc_session_jwt_secret(db: Session | None, settings: Settings) -> str | None:
    if db is None:
        return None
    row = ensure_portal_settings(db, settings)
    raw = (getattr(row, "oidc_session_jwt_secret_encrypted", None) or "").strip()
    if not raw:
        return None
    try:
        plain = decrypt_secret(raw, settings).strip()
    except ValueError:
        logger.warning("failed to decrypt portal_settings.oidc_session_jwt_secret_encrypted")
        return None
    return plain or None


def resolve_session_hop_secret(
    settings: Settings,
    db: Session | None = None,
) -> str:
    """
    Priority:
    1. ``SESSION_HOP_SECRET`` env (pytest / emergency)
    2. Process cache (after boot ensure)
    3. ``portal_settings.session_hop_secret_encrypted``
    """
    env = (settings.session_hop_secret or "").strip()
    if env:
        return env
    if _CACHED_HOP_SECRET:
        return _CACHED_HOP_SECRET
    db_plain = get_db_session_hop_secret(db, settings)
    if db_plain:
        cache_session_hop_secret(db_plain)
        return db_plain
    return ""


def ensure_portal_runtime_secrets(
    db: Session,
    settings: Settings,
    *,
    actor: str = "system",
    ip_address: str | None = None,
) -> dict[str, Any]:
    """
    Create missing HMAC secrets in ``portal_settings`` (idempotent).

    - session hop: always required outside tests — generate if DB+env empty
    - breakglass JWT: generate into DB if neither env nor UI secret exists
      (production-safe path without ``.env``)
    - OIDC session JWT (``bastion_session``): same — must survive container
      rebuilds or native SSO cookies are rejected while the registry still shows
      REGISTRE

    If env holds a value and DB is empty, copy env → DB (migrate off ``.env``).
    Never logs or returns plaintext.
    """
    from app.breakglass_secret_service import get_ui_breakglass_secret

    row = ensure_portal_settings(db, settings)
    created: list[str] = []
    migrated_from_env: list[str] = []

    hop_db = get_db_session_hop_secret(db, settings)
    hop_env = (settings.session_hop_secret or "").strip()
    if not hop_db:
        plain = hop_env or generate_cookie_secret()
        row.session_hop_secret_encrypted = encrypt_secret(plain, settings)
        if hop_env:
            migrated_from_env.append("session_hop")
        else:
            created.append("session_hop")
        cache_session_hop_secret(plain)
    else:
        cache_session_hop_secret(hop_db)

    bg_env = (settings.breakglass_jwt_secret or "").strip()
    bg_ui = get_ui_breakglass_secret(db, settings)
    if not bg_env and not bg_ui:
        plain = generate_cookie_secret()
        row.breakglass_jwt_secret_encrypted = encrypt_secret(plain, settings)
        created.append("breakglass_jwt")
        cache_breakglass_secret(plain)
    elif bg_env and not bg_ui:
        row.breakglass_jwt_secret_encrypted = encrypt_secret(bg_env, settings)
        migrated_from_env.append("breakglass_jwt")
        cache_breakglass_secret(bg_env)
    elif bg_env:
        cache_breakglass_secret(bg_env)
    elif bg_ui:
        cache_breakglass_secret(bg_ui)

    oidc_db = get_db_oidc_session_jwt_secret(db, settings)
    oidc_env = (settings.oidc_session_jwt_secret or "").strip()
    if not oidc_db:
        plain = oidc_env or generate_cookie_secret()
        row.oidc_session_jwt_secret_encrypted = encrypt_secret(plain, settings)
        if oidc_env:
            migrated_from_env.append("oidc_session_jwt")
        else:
            created.append("oidc_session_jwt")
        cache_oidc_session_jwt_secret(plain)
    else:
        cache_oidc_session_jwt_secret(oidc_db)

    if created or migrated_from_env:
        row.updated_at = utcnow()
        row.updated_by = actor
        db.commit()
        db.refresh(row)
        log_action(
            db,
            actor=actor,
            action=AUDIT_ENSURED,
            target="portal_settings",
            details={
                "created": created,
                "migrated_from_env": migrated_from_env,
            },
            ip_address=ip_address,
        )
        logger.info(
            "portal runtime secrets ensured created=%s migrated_from_env=%s",
            created,
            migrated_from_env,
        )
        # Re-read after commit so cache matches DB (created path already cached).
        if "breakglass_jwt" in created or "breakglass_jwt" in migrated_from_env:
            refreshed = get_ui_breakglass_secret(db, settings)
            if refreshed:
                cache_breakglass_secret(refreshed)
    else:
        db.commit()

    return {
        "created": created,
        "migrated_from_env": migrated_from_env,
        "session_hop_present": True,
        "breakglass_present": bool(
            bg_env or get_ui_breakglass_secret(db, settings) or get_cached_breakglass_secret()
        ),
        "oidc_session_jwt_present": bool(
            get_cached_oidc_session_jwt_secret()
            or get_db_oidc_session_jwt_secret(db, settings)
            or (settings.oidc_session_jwt_secret or "").strip()
        ),
    }


def main() -> None:
    """CLI: ``python -m app.runtime_secrets_service`` (migrate / Ansible)."""
    import sys

    from app.database import SessionLocal
    from app.sso_settings import get_settings
    from app.vault.encryption_key_store import (
        EncryptionKeyStoreError,
        ensure_encryption_key,
    )

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    settings = get_settings()
    db = SessionLocal()
    try:
        try:
            ensure_encryption_key(db, settings)
        except EncryptionKeyStoreError:
            logger.exception("encryption key store failed")
            sys.exit(2)
        result = ensure_portal_runtime_secrets(db, settings, actor="cli")
        print(
            "ok created=%s migrated_from_env=%s"
            % (result["created"], result["migrated_from_env"])
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()
