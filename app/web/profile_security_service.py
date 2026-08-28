"""Self-service password change and session revocation from /profile."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import OidcSession, RealmConfig
from app.oidc_bff import revoke_oidc_jti, validate_oidc_session_cookie
from app.oidc_bff_client import (
    InvalidCredentialsError,
    UnsupportedAuthFlowError,
    verify_keycloak_password,
)
from app.rbac.account_service import realm_provisioning_ready
from app.rbac.keycloak_admin import (
    delete_keycloak_session,
    list_keycloak_user_sessions,
    logout_keycloak_user,
    provisioning_configured,
    reset_keycloak_password,
)
from app.sso_settings import Settings
from app.web.user_context import UserContext

logger = logging.getLogger(__name__)

MIN_PASSWORD_LEN = 12
_GENERIC_FORGOT_OK = (
    "Si un compte correspond à ces informations, un email avec un nouveau mot de passe "
    "temporaire vous a été envoyé. Consultez votre boîte mail (et les spams)."
)


class ProfileSecurityError(ValueError):
    """User-facing validation or upstream failure."""


def resolve_user_realm(
    db: Session, user: UserContext, settings: Settings
) -> RealmConfig | None:
    if user.is_breakglass or not (user.keycloak_user_id or "").strip():
        return None
    slug = (user.realm_slug or "").strip()
    if slug:
        realm = db.query(RealmConfig).filter_by(slug=slug).first()
        if realm is not None:
            return realm
    return (
        db.query(RealmConfig).filter_by(is_default=True).first()
        or db.query(RealmConfig)
        .filter_by(slug=settings.sso_portal_default_realm_slug)
        .first()
    )


def self_service_security_available(
    db: Session, user: UserContext, settings: Settings
) -> bool:
    if user.is_breakglass or not (user.keycloak_user_id or "").strip():
        return False
    realm = resolve_user_realm(db, user, settings)
    return realm is not None and provisioning_configured(realm)


def _validate_new_password(
    *,
    current: str,
    new_password: str,
    confirm: str,
) -> None:
    if len(new_password) < MIN_PASSWORD_LEN:
        raise ProfileSecurityError(
            f"Le nouveau mot de passe doit contenir au moins {MIN_PASSWORD_LEN} caractères."
        )
    if new_password != confirm:
        raise ProfileSecurityError("La confirmation ne correspond pas au nouveau mot de passe.")
    if new_password == current:
        raise ProfileSecurityError(
            "Le nouveau mot de passe doit être différent de l'actuel."
        )


def current_native_jti(request: Request, db: Session, settings: Settings) -> str | None:
    cookie_name = (settings.oidc_session_cookie_name or "").strip() or "bastion_session"
    raw = request.cookies.get(cookie_name) or ""
    claims = validate_oidc_session_cookie(raw, db=db, settings=settings)
    return claims.jti if claims else None


def list_portal_native_sessions(
    db: Session,
    *,
    user: UserContext,
    current_jti: str | None,
) -> list[dict[str, Any]]:
    if not user.keycloak_user_id and not user.email and not user.username:
        return []
    subs = {user.keycloak_user_id.strip()} if user.keycloak_user_id else set()
    names = set()
    for ident in (user.email, user.username):
        v = (ident or "").strip().lower()
        if v:
            names.add(v)
    q = db.query(OidcSession).filter(OidcSession.revoked.is_(False))
    clauses = []
    if subs:
        clauses.append(OidcSession.sub.in_(subs))
    if names:
        clauses.append(OidcSession.username.in_(names))
    if not clauses:
        return []
    rows = q.filter(or_(*clauses)).order_by(OidcSession.issued_at.desc()).limit(20).all()
    out: list[dict[str, Any]] = []
    for row in rows:
        out.append(
            {
                "kind": "portal_native",
                "id": row.jti,
                "label": "Session portail (bastion_session)",
                "ip": row.ip_subnet or "—",
                "started_at": row.issued_at,
                "last_access": row.issued_at,
                "is_current": bool(current_jti and row.jti == current_jti),
                "clients": ["Portail Bastion"],
            }
        )
    return out


async def list_user_sso_sessions(
    db: Session,
    *,
    user: UserContext,
    settings: Settings,
    current_jti: str | None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = list_portal_native_sessions(
        db, user=user, current_jti=current_jti
    )
    realm = resolve_user_realm(db, user, settings)
    uid = (user.keycloak_user_id or "").strip()
    if realm is None or not uid:
        return rows
    try:
        kc_sessions = await list_keycloak_user_sessions(realm, uid, settings)
    except ValueError as exc:
        logger.warning("profile list KC sessions failed user=%s err=%s", uid, exc)
        return rows
    for sess in kc_sessions:
        sid = str(sess.get("id") or "").strip()
        if not sid:
            continue
        clients_raw = sess.get("clients") or {}
        client_names: list[str] = []
        if isinstance(clients_raw, dict):
            client_names = [str(v) for v in clients_raw.values() if v]
        started_ms = sess.get("start")
        last_ms = sess.get("lastAccess")
        rows.append(
            {
                "kind": "keycloak",
                "id": sid,
                "label": "Session SSO Keycloak",
                "ip": (sess.get("ipAddress") or "—").strip() or "—",
                "started_at": _ms_to_dt(started_ms),
                "last_access": _ms_to_dt(last_ms),
                "is_current": False,
                "clients": client_names or ["SSO"],
            }
        )
    return rows


def _ms_to_dt(value: Any) -> datetime | None:
    try:
        ms = int(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)


async def change_own_password(
    db: Session,
    *,
    user: UserContext,
    settings: Settings,
    current_password: str,
    new_password: str,
    confirm_password: str,
    actor: str,
    ip_address: str | None,
) -> None:
    realm = resolve_user_realm(db, user, settings)
    uid = (user.keycloak_user_id or "").strip()
    if realm is None or not uid:
        raise ProfileSecurityError(
            "Changement de mot de passe indisponible pour ce type de compte."
        )
    if not provisioning_configured(realm):
        raise ProfileSecurityError(
            "Le compte de service Keycloak (provisioning) n'est pas configuré pour ce realm."
        )
    _validate_new_password(
        current=current_password,
        new_password=new_password,
        confirm=confirm_password,
    )
    login_id = (user.username or user.email or "").strip()
    if not login_id:
        raise ProfileSecurityError("Identifiant de connexion introuvable pour ce compte.")
    try:
        await verify_keycloak_password(
            db,
            realm_slug=realm.slug,
            username=login_id,
            password=current_password,
            settings=settings,
        )
    except InvalidCredentialsError as exc:
        raise ProfileSecurityError("Mot de passe actuel incorrect.") from exc

    await reset_keycloak_password(
        realm,
        settings,
        keycloak_user_id=uid,
        new_password=new_password,
        temporary=False,
    )
    log_action(
        db,
        actor=actor,
        action="profile.password_changed",
        target=uid,
        details={"realm_slug": realm.slug, "self_service": True},
        ip_address=ip_address,
    )
    db.commit()


async def revoke_own_keycloak_session(
    db: Session,
    *,
    user: UserContext,
    settings: Settings,
    session_id: str,
    actor: str,
    ip_address: str | None,
) -> None:
    realm = resolve_user_realm(db, user, settings)
    uid = (user.keycloak_user_id or "").strip()
    sid = (session_id or "").strip()
    if realm is None or not uid or not sid:
        raise ProfileSecurityError("Session introuvable.")
    sessions = await list_keycloak_user_sessions(realm, uid, settings)
    owned = {str(s.get("id") or "") for s in sessions}
    if sid not in owned:
        raise ProfileSecurityError("Session introuvable ou déjà expirée.")
    await delete_keycloak_session(realm, sid, settings)
    log_action(
        db,
        actor=actor,
        action="profile.session_revoked",
        target=uid,
        details={"session_id": sid, "kind": "keycloak", "self_service": True},
        ip_address=ip_address,
    )
    db.commit()


def revoke_own_native_session(
    db: Session,
    *,
    user: UserContext,
    jti: str,
    current_jti: str | None,
    actor: str,
    ip_address: str | None,
) -> None:
    token = (jti or "").strip()
    if not token:
        raise ProfileSecurityError("Session introuvable.")
    if current_jti and token == current_jti:
        raise ProfileSecurityError(
            "Impossible de révoquer la session en cours — utilisez Déconnexion."
        )
    row = db.query(OidcSession).filter_by(jti=token, revoked=False).first()
    if row is None:
        raise ProfileSecurityError("Session introuvable ou déjà expirée.")
    uname = (row.username or "").strip().lower()
    sub = (row.sub or "").strip()
    owned = False
    if user.keycloak_user_id and sub == user.keycloak_user_id.strip():
        owned = True
    for ident in (user.email, user.username):
        v = (ident or "").strip().lower()
        if v and uname == v:
            owned = True
    if not owned:
        raise ProfileSecurityError("Session introuvable.")
    revoke_oidc_jti(db, token, revoked_by=actor, reason="profile_self_revoke")
    log_action(
        db,
        actor=actor,
        action="profile.session_revoked",
        target=sub or uname,
        details={"jti": token, "kind": "portal_native", "self_service": True},
        ip_address=ip_address,
    )
    db.commit()


async def revoke_all_other_sessions(
    db: Session,
    *,
    user: UserContext,
    settings: Settings,
    current_jti: str | None,
    actor: str,
    ip_address: str | None,
) -> int:
    """Revoke all Keycloak SSO sessions + other native JWTs (keeps current native jti)."""
    realm = resolve_user_realm(db, user, settings)
    uid = (user.keycloak_user_id or "").strip()
    count = 0
    if realm is not None and uid:
        try:
            sessions = await list_keycloak_user_sessions(realm, uid, settings)
            for sess in sessions:
                sid = str(sess.get("id") or "").strip()
                if not sid:
                    continue
                await delete_keycloak_session(realm, sid, settings)
                count += 1
        except ValueError:
            await logout_keycloak_user(realm, uid, settings)
            count += 1
    # Native sessions except current
    names = set()
    for ident in (user.email, user.username):
        v = (ident or "").strip().lower()
        if v:
            names.add(v)
    subs = {uid} if uid else set()
    q = db.query(OidcSession).filter(OidcSession.revoked.is_(False))
    clauses = []
    if subs:
        clauses.append(OidcSession.sub.in_(subs))
    if names:
        clauses.append(OidcSession.username.in_(names))
    if clauses:
        for row in q.filter(or_(*clauses)).all():
            if current_jti and row.jti == current_jti:
                continue
            revoke_oidc_jti(db, row.jti, revoked_by=actor, reason="profile_revoke_others")
            count += 1
    log_action(
        db,
        actor=actor,
        action="profile.session_revoked",
        target=uid or actor,
        details={"bulk": True, "count": count, "self_service": True},
        ip_address=ip_address,
    )
    db.commit()
    return count


async def request_forgot_password(
    db: Session,
    *,
    settings: Settings,
    realm_slug: str,
    identity: str,
    ip_address: str | None,
) -> str:
    """Always returns a generic message (no user enumeration)."""
    from app.rbac.account_service import reset_keycloak_user_password
    from app.rbac.keycloak_admin import find_keycloak_user_by_identity

    ident = (identity or "").strip()
    realm = db.query(RealmConfig).filter_by(slug=(realm_slug or "").strip()).first()
    if not ident or realm is None or not realm_provisioning_ready(realm):
        return _GENERIC_FORGOT_OK

    kc_user = await find_keycloak_user_by_identity(realm, ident, settings)

    if kc_user is None:
        log_action(
            db,
            actor=ident,
            action="auth.forgot_password",
            target=realm.slug,
            details={"ok": False, "reason": "user_not_found"},
            ip_address=ip_address,
        )
        db.commit()
        return _GENERIC_FORGOT_OK

    uid = str(kc_user.get("id") or "").strip()
    if not uid:
        return _GENERIC_FORGOT_OK

    email_error: str | None = None
    try:
        await reset_keycloak_user_password(
            db,
            settings,
            realm=realm,
            keycloak_user_id=uid,
            actor="self-service",
            ip_address=ip_address,
            username=(kc_user.get("username") or ident).strip(),
            email=(kc_user.get("email") or ident).strip(),
            send_email=True,
        )
    except Exception as exc:
        logger.warning("forgot_password reset failed ident=%s err=%s", ident, exc)
        email_error = str(exc)

    log_action(
        db,
        actor=(kc_user.get("email") or ident).strip(),
        action="auth.forgot_password",
        target=uid,
        details={
            "ok": email_error is None,
            "realm_slug": realm.slug,
            "email_error": email_error,
        },
        ip_address=ip_address,
    )
    db.commit()
    return _GENERIC_FORGOT_OK
