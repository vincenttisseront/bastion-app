"""Admin endpoints: revoke-all app sessions + Keycloak SSO logout per user."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import get_db
from app.models import RealmConfig
from app.rbac.keycloak_admin import (
    SSO_LOGOUT_RESIDUAL_NOTE,
    fetch_keycloak_user,
    logout_keycloak_user,
    search_keycloak_users,
)
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings
from app.web.sessions_service import (
    identity_match_keys,
    mark_sso_logout_requested,
    revoke_all_app_sessions_for_user,
)
from app.web.user_context import UserContext, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-user-sessions"], dependencies=[Depends(require_admin)])


def _resolve_realm(
    db: Session,
    *,
    realm_id: int | None,
    realm_slug: str | None,
) -> RealmConfig:
    realm: RealmConfig | None = None
    if realm_id is not None:
        realm = db.query(RealmConfig).filter_by(id=realm_id).first()
    elif realm_slug:
        slug = realm_slug.strip().lower()
        realm = db.query(RealmConfig).filter(RealmConfig.slug == slug).first()
        if realm is None:
            # Session registry may store Keycloak realm name, not portal slug
            realm = (
                db.query(RealmConfig)
                .filter(RealmConfig.issuer_url.contains(f"/realms/{realm_slug}"))
                .first()
            )
    if not realm:
        raise HTTPException(
            status_code=400,
            detail="Realm requis (realm_id ou realm_slug) et introuvable",
        )
    return realm


async def _resolve_kc_user(
    realm: RealmConfig,
    identity: str,
    settings: Settings,
) -> dict:
    """Resolve Keycloak user by id, else by email/username search."""
    identity = (identity or "").strip()
    if not identity:
        raise ValueError("Identité utilisateur manquante")

    user = await fetch_keycloak_user(realm, identity, settings)
    if user:
        return user

    candidates = await search_keycloak_users(realm, identity, settings, max_results=20)
    ident_l = identity.lower()
    for u in candidates:
        email = (u.get("email") or "").strip().lower()
        username = (u.get("username") or "").strip().lower()
        if email == ident_l or username == ident_l:
            return u
    if len(candidates) == 1:
        return candidates[0]
    raise ValueError(
        f"Utilisateur Keycloak introuvable pour l'identité « {identity} »"
    )


def _value_error_response(exc: ValueError) -> JSONResponse:
    return JSONResponse(
        {"ok": False, "error": str(exc), "errors": {"_form": str(exc)}},
        status_code=400,
    )


async def _do_revoke_all(
    *,
    db: Session,
    identity: str,
    realm: RealmConfig | None,
    settings: Settings,
    actor: str | None,
    ip: str | None,
) -> dict:
    if realm is not None:
        kc_user = await _resolve_kc_user(realm, identity, settings)
        emails, usernames = identity_match_keys(
            email=kc_user.get("email"),
            username=kc_user.get("username"),
        )
        identity_label = (
            kc_user.get("email")
            or kc_user.get("username")
            or kc_user.get("id")
            or identity
        )
    else:
        emails, usernames = identity_match_keys(email=identity, username=identity)
        identity_label = identity

    summary = revoke_all_app_sessions_for_user(
        db,
        identity=str(identity_label),
        emails=emails,
        usernames=usernames,
        actor=actor,
        ip_address=ip,
    )
    return {"ok": True, "action": "sessions.revoke_all_app", **summary}


async def _do_revoke_sso(
    *,
    db: Session,
    identity: str,
    realm: RealmConfig,
    settings: Settings,
    actor: str | None,
    ip: str | None,
    via: str | None = None,
) -> dict:
    kc_user = await _resolve_kc_user(realm, identity, settings)
    uid = str(kc_user.get("id") or "").strip()
    if not uid:
        raise ValueError("Réponse Keycloak sans id utilisateur")
    result = await logout_keycloak_user(realm, uid, settings)
    emails, usernames = identity_match_keys(
        email=kc_user.get("email"),
        username=kc_user.get("username"),
    )
    # Also match the path identity when it was an email/username
    path_emails, path_usernames = identity_match_keys(
        email=identity, username=identity
    )
    emails |= path_emails
    usernames |= path_usernames
    mark_sso_logout_requested(
        db,
        emails=emails,
        usernames=usernames,
        actor=actor,
    )
    details = {
        "ok": True,
        "realm_slug": result.get("realm_slug"),
        "residual_note": SSO_LOGOUT_RESIDUAL_NOTE,
        "user_email": (kc_user.get("email") or "").strip().lower() or None,
        "username": (kc_user.get("username") or "").strip().lower() or None,
    }
    if via:
        details["via"] = via
    log_action(
        db,
        actor=actor or "admin",
        action="sessions.revoke_sso",
        target=uid,
        details=details,
        ip_address=ip,
    )
    return {"ok": True, "action": "sessions.revoke_sso", **result}


@router.post("/admin/users/{identity}/sessions/revoke-all")
async def revoke_all_app_sessions(
    identity: str,
    request: Request,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_admin),
    settings: Settings = Depends(get_settings),
    realm_id: int | None = Query(None),
    realm_slug: str | None = Query(None),
):
    """
    Revoke all robotic/vault (kind=app) sessions for a user.

    identity: Keycloak user id or email/username. When realm is provided,
    Keycloak Admin is used to resolve email/username match keys.
    """
    realm = None
    if realm_id is not None or realm_slug:
        realm = _resolve_realm(db, realm_id=realm_id, realm_slug=realm_slug)
    try:
        return await _do_revoke_all(
            db=db,
            identity=identity,
            realm=realm,
            settings=settings,
            actor=user.email or user.username,
            ip=client_ip_from_request(request),
        )
    except ValueError as exc:
        return _value_error_response(exc)


@router.post("/admin/users/{identity}/sessions/revoke-sso")
async def revoke_sso_sessions(
    identity: str,
    request: Request,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_admin),
    settings: Settings = Depends(get_settings),
    realm_id: int | None = Query(None),
    realm_slug: str | None = Query(None),
):
    """
    Keycloak Admin API logout for the user (all IdP sessions).

    Does not revoke robotic/vault or break-glass. Residual oauth2-proxy cookie
    delay is documented in residual_note (≈ cookie_refresh 1h).
    """
    actor = user.email or user.username
    ip = client_ip_from_request(request)
    try:
        realm = _resolve_realm(db, realm_id=realm_id, realm_slug=realm_slug)
        return await _do_revoke_sso(
            db=db,
            identity=identity,
            realm=realm,
            settings=settings,
            actor=actor,
            ip=ip,
        )
    except ValueError as exc:
        log_action(
            db,
            actor=actor or "admin",
            action="sessions.revoke_sso",
            target=identity,
            details={"ok": False, "error": str(exc)},
            ip_address=ip,
        )
        return _value_error_response(exc)


@router.post("/admin/users/{identity}/sessions/disconnect")
async def disconnect_user(
    identity: str,
    request: Request,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_admin),
    settings: Settings = Depends(get_settings),
    realm_id: int | None = Query(None),
    realm_slug: str | None = Query(None),
):
    """
    Combined admin action: (a) revoke-all app sessions, then (b) Keycloak logout.

    Returns both results separately — never a single binary status that would hide
    a partial success. Break-glass is explicitly out of scope.
    """
    actor = user.email or user.username
    ip = client_ip_from_request(request)

    realm: RealmConfig | None = None
    realm_error: str | None = None
    try:
        realm = _resolve_realm(db, realm_id=realm_id, realm_slug=realm_slug)
    except HTTPException as exc:
        realm_error = (
            exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        )

    # --- (a) app sessions (works with or without realm) ---
    try:
        app_result = await _do_revoke_all(
            db=db,
            identity=identity,
            realm=realm,
            settings=settings,
            actor=actor,
            ip=ip,
        )
    except ValueError as exc:
        app_result = {
            "ok": False,
            "error": str(exc),
            "revoked_count": 0,
            "failed_count": 0,
            "revoked": [],
            "failed": [],
        }

    # --- (b) SSO logout ---
    if realm is None:
        sso_result = {
            "ok": False,
            "error": realm_error or "Realm requis pour le logout SSO",
            "residual_note": SSO_LOGOUT_RESIDUAL_NOTE,
        }
        log_action(
            db,
            actor=actor or "admin",
            action="sessions.revoke_sso",
            target=identity,
            details={"ok": False, "error": sso_result["error"], "via": "disconnect"},
            ip_address=ip,
        )
    else:
        try:
            sso_result = await _do_revoke_sso(
                db=db,
                identity=identity,
                realm=realm,
                settings=settings,
                actor=actor,
                ip=ip,
                via="disconnect",
            )
        except ValueError as exc:
            sso_result = {
                "ok": False,
                "error": str(exc),
                "residual_note": SSO_LOGOUT_RESIDUAL_NOTE,
            }
            log_action(
                db,
                actor=actor or "admin",
                action="sessions.revoke_sso",
                target=identity,
                details={"ok": False, "error": str(exc), "via": "disconnect"},
                ip_address=ip,
            )

    return {
        "app_sessions": app_result,
        "sso": sso_result,
        "breakglass": {
            "included": False,
            "note": "Le break-glass a son propre bouton de révocation (hors périmètre).",
        },
    }
