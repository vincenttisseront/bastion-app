"""Resolve OIDC session email from Keycloak when oauth2-proxy did not forward it.

``insecure_oidc_allow_unverified_email`` only helps when the IdP *emits* an email
claim with ``email_verified=false``. If Keycloak/AD has no email on the user,
or the claim is absent from the token, X-Email stays empty and bastion used to
fall back to preferred_username (breaks identity_format=email apps).
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.models import RealmConfig
from app.rbac.keycloak_admin import fetch_keycloak_user
from app.sso_settings import Settings
from app.web.user_context import UserContext, looks_like_uuid

logger = logging.getLogger(__name__)


def looks_like_email(value: str | None) -> bool:
    text = (value or "").strip()
    return bool(text) and "@" in text and not looks_like_uuid(text)


def keycloak_email_diagnostics(kc_user: dict[str, Any] | None) -> dict[str, Any]:
    """Admin-facing snapshot of Keycloak email fields vs OIDC readiness."""
    if not kc_user:
        return {
            "email": None,
            "email_verified": None,
            "has_email": False,
            "oidc_claim_ready": False,
            "warning": "Utilisateur Keycloak introuvable",
        }
    email = (kc_user.get("email") or "").strip() or None
    verified = kc_user.get("emailVerified")
    has_email = looks_like_email(email)
    if not has_email:
        warning = (
            "Pas d'email dans Keycloak — le token OIDC n'émettra pas de claim email. "
            "Renseignez Email sur la fiche utilisateur (ou le mapper LDAP mail/userPrincipalName)."
        )
    elif verified is False:
        warning = (
            "Email présent mais emailVerified=false. "
            "Nécessite insecure_oidc_allow_unverified_email côté oauth2-proxy (apply infra)."
        )
    else:
        warning = None
    return {
        "email": email,
        "email_verified": verified,
        "has_email": has_email,
        "oidc_claim_ready": has_email,
        "warning": warning,
    }


def _realm_for_user(db: Session, user: UserContext, settings: Settings) -> RealmConfig | None:
    if user.realm_slug:
        realm = (
            db.query(RealmConfig)
            .filter_by(slug=user.realm_slug, enabled=True)
            .first()
        )
        if realm:
            return realm
    return (
        db.query(RealmConfig)
        .filter_by(slug=settings.sso_portal_default_realm_slug, enabled=True)
        .first()
        or db.query(RealmConfig).filter_by(is_default=True, enabled=True).first()
    )


async def resolve_user_email(
    db: Session,
    settings: Settings,
    user: UserContext,
) -> str:
    """
    Prefer session X-Email when it looks like a real address; otherwise load
    email from Keycloak Admin API (source of truth for AD-synced users).
    """
    session_email = (user.email or "").strip()
    if looks_like_email(session_email):
        return session_email

    if not user.keycloak_user_id:
        return session_email

    realm = _realm_for_user(db, user, settings)
    if realm is None:
        return session_email
    # Need Admin API credentials — do not require groups_sync_enabled (email lookup ≠ group sync).
    if not realm.keycloak_admin_client_id or not realm.keycloak_admin_client_secret_encrypted:
        return session_email

    try:
        kc_user = await fetch_keycloak_user(realm, user.keycloak_user_id, settings)
    except Exception:
        logger.exception(
            "keycloak email lookup failed (user=%s realm=%s)",
            user.keycloak_user_id,
            getattr(realm, "slug", None),
        )
        return session_email

    email = (kc_user or {}).get("email") if kc_user else None
    email = (email or "").strip()
    if looks_like_email(email):
        return email
    return session_email
