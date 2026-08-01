"""Per-realm OIDC BFF client config (Fernet secrets) + global session JWT secret."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models import RealmConfig
from app.portal_settings_service import ensure_portal_settings
from app.secret_crypto import decrypt_secret, encrypt_secret, encryption_configured
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

AUDIT_BFF_CONFIG_SET = "realm.oidc_bff_config_set"
AUDIT_SESSION_SECRET_GENERATED = "oidc_session_jwt_secret_generated"


@dataclass(frozen=True, slots=True)
class OidcBffConfig:
    """Plaintext BFF client config for server-side use only — never serialize to API/logs."""

    realm_slug: str
    keycloak_base_url: str
    client_id: str
    client_secret: str
    redirect_uri: str


def _normalize_base_url(url: str) -> str:
    return (url or "").strip().rstrip("/")


def get_oidc_bff_config(
    db: Session,
    realm_slug: str,
    settings: Settings,
) -> OidcBffConfig | None:
    """
    Load and decrypt BFF client config for ``realm_slug``.

    Returns None if the realm is missing or BFF fields are incomplete.
    Never logs or returns secrets via side channels.
    """
    slug = (realm_slug or "").strip()
    if not slug:
        return None
    realm = db.query(RealmConfig).filter_by(slug=slug).first()
    if realm is None:
        realm = db.query(RealmConfig).filter(RealmConfig.slug.ilike(slug)).first()
    if realm is None:
        return None

    base = _normalize_base_url(realm.oidc_keycloak_base_url or "")
    client_id = (realm.oidc_bff_client_id or "").strip()
    redirect_uri = (realm.oidc_bff_redirect_uri or "").strip()
    enc = (realm.oidc_bff_client_secret_encrypted or "").strip()
    if not (base and client_id and redirect_uri and enc):
        return None
    if not encryption_configured(settings):
        logger.warning("oidc_bff config present but encryption not configured")
        return None
    try:
        client_secret = decrypt_secret(enc, settings).strip()
    except ValueError:
        logger.warning("failed to decrypt oidc_bff client secret realm=%s", slug)
        return None
    if not client_secret:
        return None
    return OidcBffConfig(
        realm_slug=realm.slug,
        keycloak_base_url=base,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
    )


def set_oidc_bff_config(
    db: Session,
    realm_slug: str,
    settings: Settings,
    *,
    base_url: str,
    client_id: str,
    client_secret: str | None,
    redirect_uri: str,
    keep_existing_secret: bool = False,
) -> RealmConfig:
    """
    Write/update BFF client fields. Empty ``client_secret`` keeps the current
    ciphertext when ``keep_existing_secret`` is True (edit form pattern).
    """
    if not encryption_configured(settings):
        raise ValueError("Chiffrement Fernet non configuré")

    slug = (realm_slug or "").strip()
    realm = db.query(RealmConfig).filter_by(slug=slug).first()
    if realm is None:
        raise LookupError(f"realm not found: {slug}")

    base = _normalize_base_url(base_url)
    cid = (client_id or "").strip()
    redir = (redirect_uri or "").strip()
    if not base or not cid or not redir:
        raise ValueError("base_url, client_id et redirect_uri sont requis")

    secret_plain = (client_secret or "").strip()
    if secret_plain:
        realm.oidc_bff_client_secret_encrypted = encrypt_secret(secret_plain, settings)
    elif keep_existing_secret and (realm.oidc_bff_client_secret_encrypted or "").strip():
        pass
    else:
        raise ValueError("client_secret requis")

    realm.oidc_keycloak_base_url = base
    realm.oidc_bff_client_id = cid
    realm.oidc_bff_redirect_uri = redir
    db.flush()
    return realm


def oidc_bff_config_status(realm: RealmConfig) -> dict[str, bool | str]:
    """Booléans-only status for Admin UI (never plaintext secrets)."""
    has_secret = bool((realm.oidc_bff_client_secret_encrypted or "").strip())
    base = _normalize_base_url(realm.oidc_keycloak_base_url or "")
    cid = (realm.oidc_bff_client_id or "").strip()
    redir = (realm.oidc_bff_redirect_uri or "").strip()
    complete = bool(base and cid and redir and has_secret)
    return {
        "configured": complete,
        "has_client_secret": has_secret,
        "base_url": base,
        "client_id": cid,
        "redirect_uri": redir,
    }


def resolve_oidc_session_jwt_secret(
    db: Session | None,
    settings: Settings,
) -> str:
    """
    Global portal HMAC for ``bastion_session`` (not per-realm).

    Priority: env ``OIDC_SESSION_JWT_SECRET`` → PortalSettings encrypted → settings auto.
    """
    env = (settings.oidc_session_jwt_secret or "").strip()
    if env:
        return env
    if db is not None:
        row = ensure_portal_settings(db, settings)
        raw = (row.oidc_session_jwt_secret_encrypted or "").strip()
        if raw:
            try:
                plain = decrypt_secret(raw, settings).strip()
                if plain:
                    return plain
            except ValueError:
                logger.warning("failed to decrypt portal oidc_session_jwt_secret")
    # Settings validator always mints a process secret if empty.
    return (settings.oidc_session_jwt_secret or "").strip()


def generate_oidc_session_jwt_secret(
    db: Session,
    settings: Settings,
    *,
    realm_slug: str | None = None,
    actor: str | None = None,
) -> str:
    """
    Generate a new global OIDC session HMAC, store Fernet-encrypted in PortalSettings.

    ``realm_slug`` is accepted for API symmetry with per-realm helpers but ignored:
    the session JWT secret is portal-global (same design as ``OIDC_SESSION_JWT_SECRET``).

    Returns the plaintext once for the caller to discard after use — never log it.
    """
    _ = realm_slug
    if not encryption_configured(settings):
        raise ValueError("Chiffrement Fernet non configuré")
    plain = secrets.token_urlsafe(32)
    row = ensure_portal_settings(db, settings)
    row.oidc_session_jwt_secret_encrypted = encrypt_secret(plain, settings)
    if actor:
        row.updated_by = actor
    db.flush()
    return plain


async def ping_oidc_discovery(base_url: str, realm_slug: str) -> dict[str, str | bool]:
    """GET ``{base}/realms/{realm}/.well-known/openid-configuration`` (no secrets)."""
    import httpx

    base = _normalize_base_url(base_url)
    slug = (realm_slug or "").strip()
    if not base or not slug:
        return {"ok": False, "error": "base_url et realm requis"}
    url = f"{base}/realms/{slug}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        return {"ok": False, "error": type(exc).__name__, "url": url}
    if resp.status_code != 200:
        return {"ok": False, "error": f"HTTP {resp.status_code}", "url": url}
    try:
        data = resp.json()
    except Exception:
        return {"ok": False, "error": "réponse non-JSON", "url": url}
    issuer = (data.get("issuer") or "") if isinstance(data, dict) else ""
    return {"ok": True, "url": url, "issuer": issuer}
