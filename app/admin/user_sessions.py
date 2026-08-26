"""Admin endpoints: revoke-all app sessions + Keycloak SSO logout per user."""

from __future__ import annotations

import logging
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import get_db
from app.models import BastionAccount, RealmConfig
from app.oidc_bff import revoke_oidc_sessions_for_identity
from app.rbac.keycloak_admin import (
    SSO_LOGOUT_RESIDUAL_NOTE,
    fetch_keycloak_user,
    logout_keycloak_user,
    search_keycloak_users,
    _admin_get,
)
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings
from app.web.sessions_service import (
    identity_match_keys,
    mark_sso_logout_requested,
    remove_portal_sessions_for_identity,
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


def _bastion_account_for_identity(
    db: Session,
    identity: str,
    *,
    realm: RealmConfig | None = None,
) -> BastionAccount | None:
    ident = (identity or "").strip().lower()
    if not ident:
        return None
    q = db.query(BastionAccount).filter(
        or_(
            func.lower(BastionAccount.email) == ident,
            func.lower(BastionAccount.username) == ident,
        )
    )
    if realm is not None:
        q = q.filter(BastionAccount.realm_id == realm.id)
    row = q.order_by(BastionAccount.id.desc()).first()
    if row is not None:
        return row
    if realm is not None:
        # Wrong realm on the session card — try any realm for this identity.
        return (
            db.query(BastionAccount)
            .filter(
                or_(
                    func.lower(BastionAccount.email) == ident,
                    func.lower(BastionAccount.username) == ident,
                )
            )
            .order_by(BastionAccount.id.desc())
            .first()
        )
    return None


async def _users_by_exact_attr(
    realm: RealmConfig,
    settings: Settings,
    *,
    attr: str,
    value: str,
) -> list[dict]:
    """Keycloak Admin exact match on email or username."""
    q = (value or "").strip()
    if not q or attr not in {"email", "username"}:
        return []
    resp = await _admin_get(
        realm,
        settings,
        f"/users?{attr}={quote(q)}&exact=true&max=5",
    )
    if resp.status_code == 403:
        from app.rbac.keycloak_admin import _view_users_error

        raise ValueError(_view_users_error())
    if resp.status_code >= 400:
        return []
    data = resp.json()
    return data if isinstance(data, list) else []


async def _resolve_kc_user(
    realm: RealmConfig,
    identity: str,
    settings: Settings,
    *,
    db: Session | None = None,
) -> dict:
    """Resolve Keycloak user by id, BastionAccount, exact email/username, then search."""
    identity = (identity or "").strip()
    if not identity:
        raise ValueError("Identité utilisateur manquante")

    # UUID / Keycloak id
    user = await fetch_keycloak_user(realm, identity, settings)
    if user:
        return user

    if db is not None:
        account = _bastion_account_for_identity(db, identity, realm=realm)
        kc_id = (account.keycloak_user_id or "").strip() if account else ""
        if account and kc_id:
            fetch_realm = realm
            if account.realm_id != realm.id and account.realm is not None:
                fetch_realm = account.realm
            user = await fetch_keycloak_user(fetch_realm, kc_id, settings)
            if user:
                if fetch_realm.id != realm.id:
                    user = dict(user)
                    user["_bastion_realm_slug"] = fetch_realm.slug
                return user

    ident_l = identity.lower()
    for attr in ("email", "username"):
        exact = await _users_by_exact_attr(realm, settings, attr=attr, value=identity)
        for u in exact:
            email = (u.get("email") or "").strip().lower()
            username = (u.get("username") or "").strip().lower()
            if email == ident_l or username == ident_l:
                return u
        if len(exact) == 1:
            return exact[0]

    candidates = await search_keycloak_users(realm, identity, settings, max_results=20)
    for u in candidates:
        email = (u.get("email") or "").strip().lower()
        username = (u.get("username") or "").strip().lower()
        if email == ident_l or username == ident_l:
            return u
    if len(candidates) == 1:
        return candidates[0]
    raise ValueError(
        f"Utilisateur Keycloak introuvable pour l'identité « {identity} » "
        f"(realm « {realm.slug} »). Vérifiez le realm de la session et "
        "l'email/username Keycloak."
    )


def _value_error_response(exc: ValueError) -> JSONResponse:
    return JSONResponse(
        {"ok": False, "error": str(exc), "errors": {"_form": str(exc)}},
        status_code=400,
    )


def _apply_local_session_revocation(
    db: Session,
    *,
    identity: str,
    realm_slug: str | None,
    emails: set[str],
    usernames: set[str],
    keycloak_subs: set[str],
    actor: str | None,
) -> dict:
    """Always revoke native JWT + drop portal registry rows (even if KC logout fails)."""
    path_emails, path_usernames = identity_match_keys(
        email=identity, username=identity
    )
    emails = set(emails) | path_emails
    usernames = set(usernames) | path_usernames
    native = revoke_oidc_sessions_for_identity(
        db,
        realm_slug=realm_slug,
        emails=emails,
        usernames=usernames,
        keycloak_subs=keycloak_subs,
        revoked_by=actor or "admin",
        reason="admin_disconnect",
    )
    # Also revoke native sessions without realm filter if realm was wrong/empty.
    if realm_slug and native == 0:
        native = revoke_oidc_sessions_for_identity(
            db,
            realm_slug=None,
            emails=emails,
            usernames=usernames,
            keycloak_subs=keycloak_subs,
            revoked_by=actor or "admin",
            reason="admin_disconnect",
        )
    stamped = mark_sso_logout_requested(
        db, emails=emails, usernames=usernames, actor=actor
    )
    removed = remove_portal_sessions_for_identity(
        db, emails=emails, usernames=usernames, realm_slug=None
    )
    try:
        db.commit()
    except Exception:
        db.rollback()
    return {
        "native_oidc_revoked": native,
        "portal_rows_stamped": stamped,
        "portal_rows_removed": removed,
    }


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
        kc_user = await _resolve_kc_user(realm, identity, settings, db=db)
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
    kc_user = await _resolve_kc_user(realm, identity, settings, db=db)
    alt_slug = (kc_user.get("_bastion_realm_slug") or "").strip()
    logout_realm = realm
    if alt_slug and alt_slug != realm.slug:
        alt = db.query(RealmConfig).filter_by(slug=alt_slug).first()
        if alt is not None:
            logout_realm = alt
    uid = str(kc_user.get("id") or "").strip()
    if not uid:
        raise ValueError("Réponse Keycloak sans id utilisateur")

    emails, usernames = identity_match_keys(
        email=kc_user.get("email"),
        username=kc_user.get("username"),
    )
    path_emails, path_usernames = identity_match_keys(
        email=identity, username=identity
    )
    emails |= path_emails
    usernames |= path_usernames

    logout_error: str | None = None
    result: dict = {
        "ok": False,
        "keycloak_user_id": uid,
        "realm_slug": logout_realm.slug,
        "residual_note": SSO_LOGOUT_RESIDUAL_NOTE,
    }
    try:
        result = await logout_keycloak_user(logout_realm, uid, settings)
    except ValueError as exc:
        logout_error = str(exc)

    local = _apply_local_session_revocation(
        db,
        identity=identity,
        realm_slug=logout_realm.slug,
        emails=emails,
        usernames=usernames,
        keycloak_subs={uid},
        actor=actor,
    )
    details = {
        "ok": logout_error is None,
        "realm_slug": result.get("realm_slug") or logout_realm.slug,
        "residual_note": SSO_LOGOUT_RESIDUAL_NOTE,
        "user_email": (kc_user.get("email") or "").strip().lower() or None,
        "username": (kc_user.get("username") or "").strip().lower() or None,
        **local,
    }
    if via:
        details["via"] = via
    if logout_error:
        details["error"] = logout_error
    log_action(
        db,
        actor=actor or "admin",
        action="sessions.revoke_sso",
        target=uid,
        details=details,
        ip_address=ip,
    )
    if logout_error:
        return {
            "ok": False,
            "error": logout_error,
            "action": "sessions.revoke_sso",
            "keycloak_user_id": uid,
            "realm_slug": logout_realm.slug,
            "residual_note": SSO_LOGOUT_RESIDUAL_NOTE,
            **local,
        }
    return {"ok": True, "action": "sessions.revoke_sso", **result, **local}


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

    Also revokes native bastion_session JWTs and drops portal registry rows.
    Residual oauth2-proxy cookie delay is documented in residual_note (≈ cookie_refresh 1h).
    """
    actor = user.email or user.username
    ip = client_ip_from_request(request)
    try:
        realm = _resolve_realm(db, realm_id=realm_id, realm_slug=realm_slug)
        result = await _do_revoke_sso(
            db=db,
            identity=identity,
            realm=realm,
            settings=settings,
            actor=actor,
            ip=ip,
        )
        if result.get("ok") is False:
            return _value_error_response(
                ValueError(result.get("error") or "Échec SSO")
            )
        return result
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
    Combined admin action: (a) revoke-all app sessions, then (b) Keycloak logout,
    and always (c) revoke native bastion_session + drop portal ActiveSession rows.

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
            # Resolve / pre-logout failures — IdP logout never ran; still clear locally below.
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

    # --- (c) clear native JWT + portal registry when IdP path did not already ---
    if "native_oidc_revoked" not in sso_result:
        local = _apply_local_session_revocation(
            db,
            identity=identity,
            realm_slug=realm.slug if realm is not None else None,
            emails=set(),
            usernames=set(),
            keycloak_subs=set(),
            actor=actor,
        )
        sso_result = {**sso_result, **local}

    return {
        "app_sessions": app_result,
        "sso": sso_result,
        "breakglass": {
            "included": False,
            "note": "Le break-glass a son propre bouton de révocation (hors périmètre).",
        },
    }
