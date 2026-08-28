"""End-user portal — application launcher (/apps) and profile (/profile)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.access_modes import app_launch_url
from app.admin.activesync_devices import serialize_device
from app.audit import log_action
from app.database import get_db
from app.models import App, RealmConfig
from app.rbac.effective_access_service import get_effective_apps_for_user
from app.sso_settings import Settings, get_settings
from app.subdomain import activesync_device_service as device_service
from app.subdomain.activesync_device_service import DeviceDecisionError
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context, flash_redirect, verify_csrf_token
from app.request_client_ip import client_ip_from_request
from app.web.sessions_service import touch_app_session, touch_portal_session
from app.web.templates import render
from app.web.user_context import UserContext, is_portal_admin, require_user_enriched

router = APIRouter(tags=["portal"], dependencies=[Depends(require_user_enriched)])

# Human-readable access status for end-user surfaces (never expose raw levels).
_ACCESS_STATUS = {
    "view": "Lecture seule",
    "launch": "Ouverture",
    "manage": "Gestion",
}


def _ctx(request: Request, settings: Settings, **extra):
    return base_template_context(request, settings, APP_VERSION, **extra)


def _client_ip(request: Request) -> str:
    return client_ip_from_request(request)


def _resolve_portal_admin(user: UserContext, db: Session, settings: Settings) -> bool:
    portal_admin = is_portal_admin(user, db, settings)
    if portal_admin:
        user.is_admin = True
    return portal_admin


def _portal_page_ctx(
    request: Request,
    settings: Settings,
    *,
    user: UserContext,
    portal_admin: bool,
    **extra,
) -> dict:
    """Build template context with is_admin always reflecting portal_admin resolution."""
    ctx = _ctx(
        request,
        settings,
        hide_chrome=True,
        is_admin=portal_admin,
        is_portal_admin=portal_admin,
        portal_user=user,
        **extra,
    )
    # Defend against base_template_context overwriting — keep resolved admin flag.
    ctx["is_admin"] = portal_admin
    ctx["is_portal_admin"] = portal_admin
    return ctx


def _effective_tiles(db: Session, user: UserContext) -> list[dict]:
    from app.bastion.bastion_fields import (
        normalize_credential_mode,
        resolve_identity_login_username,
    )
    from app.web.app_logos import logo_public_url
    from app.web.portal_enrichment import enrich_tile
    from app.vault.user_app_credential_service import needs_individual_credential_setup

    entries = get_effective_apps_for_user(
        db,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
    )
    tiles: list[dict] = []
    for entry in entries:
        needs_credential_setup = needs_individual_credential_setup(
            db,
            entry.app,
            user.keycloak_user_id,
            group_names=user.groups,
        )
        can_launch = entry.can_launch and not needs_credential_setup
        cred_mode = normalize_credential_mode(entry.app.credential_mode)
        identity_login = ""
        if cred_mode == "identite_utilisateur":
            identity_login = resolve_identity_login_username(
                email=user.email,
                username=user.username,
                identity_format=getattr(entry.app, "identity_format", None),
            )
        tile = {
            "id": entry.app.id,
            "slug": entry.app.slug,
            "label": entry.app.label,
            "description": entry.app.description or "",
            "access_mode": entry.app.access_mode,
            "access_level": entry.access_level,
            "access_status": _ACCESS_STATUS.get(entry.access_level, "Accès"),
            "can_launch": can_launch,
            "needs_credential_setup": needs_credential_setup,
            "credential_mode": cred_mode,
            "identity_login": identity_login,
            "launch_url": app_launch_url(entry.app),
            "logo_url": logo_public_url(entry.app),
            "tile_icon": entry.app.tile_icon,
        }
        tiles.append(enrich_tile(entry.app, tile))
    return tiles


def _account_console_url(db: Session, user: UserContext, settings: Settings) -> str | None:
    """Keycloak Account Console URL for the user's realm (self-service)."""
    if user.is_breakglass:
        return None
    realm = (
        db.query(RealmConfig).filter_by(slug=user.realm_slug).first()
        or db.query(RealmConfig).filter_by(is_default=True).first()
        or db.query(RealmConfig).filter_by(slug=settings.sso_portal_default_realm_slug).first()
    )
    if realm is None or not realm.issuer_url:
        return None
    return f"{realm.issuer_url.rstrip('/')}/account/"


def _portal_activesync_context(db: Session, user: UserContext) -> dict:
    """Devices owned by the session identity + actionable pending for banners."""
    devices = device_service.devices_for_identities(
        db,
        user_keys=[user.email or "", user.username or ""],
        keycloak_user_id=user.keycloak_user_id,
    )
    devices = device_service.repair_domain_prefixed_user_keys(db, devices)
    device_service.link_devices_to_keycloak_user(
        db,
        devices=devices,
        keycloak_user_id=user.keycloak_user_id,
        realm_id=None,
    )
    apps_by_id = {a.id: a for a in db.query(App).all()}
    rows = []
    pending_actionable = []
    for device in devices:
        if not device_service.device_owned_by_session(
            device,
            email=user.email,
            username=user.username,
            keycloak_user_id=user.keycloak_user_id,
        ):
            continue
        row = serialize_device(device, apps_by_id.get(device.application_id))
        rows.append(row)
        if row["status"] == "pending" and row.get("app_device_control"):
            pending_actionable.append(row)
    return {
        "activesync_devices": rows,
        "activesync_pending": pending_actionable,
        "activesync_pending_count": len(pending_actionable),
    }


@router.get("/apps")
async def apps_portal(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    """User home: grid of applications the caller may access."""
    if user.is_breakglass:
        return RedirectResponse(url="/dashboard", status_code=302)

    touch_portal_session(db, user, _client_ip(request), request=request)
    portal_admin = _resolve_portal_admin(user, db, settings)
    tiles = _effective_tiles(db, user)
    from app.web.portal_enrichment import build_apps_sections
    from app.web.portal_favorites import list_favorite_app_ids

    favorite_ids = list_favorite_app_ids(db, user.keycloak_user_id)
    fav_set = set(favorite_ids)
    for tile in tiles:
        tile["is_favorite"] = tile.get("id") in fav_set
    sections = build_apps_sections(tiles, favorite_ids=favorite_ids)
    as_ctx = _portal_activesync_context(db, user)
    return render(
        "portal/apps.html",
        **_portal_page_ctx(
            request,
            settings,
            user=user,
            portal_admin=portal_admin,
            apps=tiles,
            greeting_name=user.first_name,
            apps_sections=sections,
            **as_ctx,
        ),
    )


@router.get("/profile")
async def user_profile(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    """End-user profile: identity, app summary, Keycloak account security link."""
    touch_portal_session(db, user, _client_ip(request), request=request)
    portal_admin = _resolve_portal_admin(user, db, settings)
    tiles = _effective_tiles(db, user)
    account_url = _account_console_url(db, user, settings)
    as_ctx = _portal_activesync_context(db, user)
    from app.web.profile_security_service import (
        current_native_jti,
        list_user_sso_sessions,
        self_service_security_available,
    )

    security_available = self_service_security_available(db, user, settings)
    current_jti = current_native_jti(request, db, settings)
    sso_sessions: list = []
    if security_available:
        sso_sessions = await list_user_sso_sessions(
            db,
            user=user,
            settings=settings,
            current_jti=current_jti,
        )
    return render(
        "portal/profile.html",
        **_portal_page_ctx(
            request,
            settings,
            user=user,
            portal_admin=portal_admin,
            apps=tiles,
            apps_preview=tiles[:6],
            account_url=account_url,
            role_label="Administrateur" if portal_admin else "Utilisateur",
            security_available=security_available,
            sso_sessions=sso_sessions,
            min_password_len=12,
            **as_ctx,
        ),
    )


def _owned_device_or_404(db: Session, device_id: int, user: UserContext):
    from app.models import ActiveSyncDevice

    device = db.get(ActiveSyncDevice, device_id)
    if device is None or not device_service.device_owned_by_session(
        device,
        email=user.email,
        username=user.username,
        keycloak_user_id=user.keycloak_user_id,
    ):
        raise HTTPException(status_code=404, detail="Appareil introuvable")
    return device


def _require_portal_csrf(request: Request, settings: Settings, csrf_token: str) -> None:
    # Must match base_template_context's fallback ("dev-insecure").
    secret = settings.vault_portal_internal_token or "dev-insecure"
    if not verify_csrf_token(request, secret, csrf_token):
        raise HTTPException(status_code=403, detail="Jeton CSRF invalide")


@router.post("/profile/activesync/devices/{device_id}/approve")
async def portal_device_approve(
    device_id: int,
    request: Request,
    csrf_token: str = Form(""),
    friendly_name: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    _require_portal_csrf(request, settings, csrf_token)
    device = _owned_device_or_404(db, device_id, user)
    secret = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/profile#section-devices", status_code=302)
    try:
        device_service.user_approve_device(
            db,
            device,
            actor=user.email or user.username or "user",
            friendly_name=friendly_name or None,
        )
    except DeviceDecisionError as exc:
        flash_redirect(response, str(exc), "error", secret)
        return response
    flash_redirect(
        response,
        "Appareil approuvé — la synchronisation peut reprendre dans quelques minutes.",
        "success",
        secret,
    )
    return response


@router.post("/profile/activesync/devices/{device_id}/reject")
async def portal_device_reject(
    device_id: int,
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    _require_portal_csrf(request, settings, csrf_token)
    device = _owned_device_or_404(db, device_id, user)
    secret = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/profile#section-devices", status_code=302)
    try:
        device_service.user_reject_device(
            db, device, actor=user.email or user.username or "user"
        )
    except DeviceDecisionError as exc:
        flash_redirect(response, str(exc), "error", secret)
        return response
    flash_redirect(
        response,
        "Appareil refusé — s'il ne s'agissait pas de vous, changez votre mot de passe.",
        "success",
        secret,
    )
    return response


@router.post("/profile/activesync/devices/{device_id}/revoke")
async def portal_device_revoke(
    device_id: int,
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    _require_portal_csrf(request, settings, csrf_token)
    device = _owned_device_or_404(db, device_id, user)
    secret = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/profile#section-devices", status_code=302)
    try:
        device_service.user_revoke_device(
            db, device, actor=user.email or user.username or "user"
        )
    except DeviceDecisionError as exc:
        flash_redirect(response, str(exc), "error", secret)
        return response
    flash_redirect(
        response,
        "Appareil révoqué — la synchronisation sera refusée à la prochaine tentative.",
        "success",
        secret,
    )
    return response


@router.post("/profile/password")
async def profile_change_password(
    request: Request,
    csrf_token: str = Form(""),
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    from app.web.profile_security_service import (
        ProfileSecurityError,
        change_own_password,
        self_service_security_available,
    )

    _require_portal_csrf(request, settings, csrf_token)
    secret = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/profile#section-security", status_code=302)
    if not self_service_security_available(db, user, settings):
        flash_redirect(response, "Changement de mot de passe indisponible.", "error", secret)
        return response
    actor = user.email or user.username or "user"
    try:
        await change_own_password(
            db,
            user=user,
            settings=settings,
            current_password=current_password,
            new_password=new_password,
            confirm_password=confirm_password,
            actor=actor,
            ip_address=_client_ip(request),
        )
    except ProfileSecurityError as exc:
        flash_redirect(response, str(exc), "error", secret)
        return response
    flash_redirect(response, "Mot de passe mis à jour.", "success", secret)
    return response


@router.post("/profile/sessions/revoke")
async def profile_revoke_session(
    request: Request,
    csrf_token: str = Form(""),
    session_kind: str = Form(""),
    session_id: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    from app.web.profile_security_service import (
        ProfileSecurityError,
        current_native_jti,
        revoke_own_keycloak_session,
        revoke_own_native_session,
        self_service_security_available,
    )

    _require_portal_csrf(request, settings, csrf_token)
    secret = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/profile#section-security", status_code=302)
    if not self_service_security_available(db, user, settings):
        flash_redirect(response, "Révocation indisponible.", "error", secret)
        return response
    actor = user.email or user.username or "user"
    kind = (session_kind or "").strip()
    sid = (session_id or "").strip()
    try:
        if kind == "keycloak":
            await revoke_own_keycloak_session(
                db,
                user=user,
                settings=settings,
                session_id=sid,
                actor=actor,
                ip_address=_client_ip(request),
            )
        elif kind == "portal_native":
            revoke_own_native_session(
                db,
                user=user,
                jti=sid,
                current_jti=current_native_jti(request, db, settings),
                actor=actor,
                ip_address=_client_ip(request),
            )
        else:
            raise ProfileSecurityError("Session introuvable.")
    except ProfileSecurityError as exc:
        flash_redirect(response, str(exc), "error", secret)
        return response
    flash_redirect(response, "Session révoquée.", "success", secret)
    return response


@router.post("/profile/sessions/revoke-others")
async def profile_revoke_other_sessions(
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    from app.web.profile_security_service import (
        ProfileSecurityError,
        current_native_jti,
        revoke_all_other_sessions,
        self_service_security_available,
    )

    _require_portal_csrf(request, settings, csrf_token)
    secret = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/profile#section-security", status_code=302)
    if not self_service_security_available(db, user, settings):
        flash_redirect(response, "Révocation indisponible.", "error", secret)
        return response
    actor = user.email or user.username or "user"
    try:
        count = await revoke_all_other_sessions(
            db,
            user=user,
            settings=settings,
            current_jti=current_native_jti(request, db, settings),
            actor=actor,
            ip_address=_client_ip(request),
        )
    except ProfileSecurityError as exc:
        flash_redirect(response, str(exc), "error", secret)
        return response
    flash_redirect(
        response,
        f"{count} session{'s' if count != 1 else ''} révoquée{'s' if count != 1 else ''}.",
        "success",
        secret,
    )
    return response


@router.post("/api/apps/{app_id}/launch-ping")
async def app_launch_ping(
    app_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_user_enriched),
):
    """Fire-and-forget audit when the user clicks Open on a tile."""
    entries = get_effective_apps_for_user(
        db,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
    )
    match = next((e for e in entries if e.app.id == app_id), None)
    if match is None:
        return JSONResponse({"ok": False, "detail": "App not accessible"}, status_code=404)
    if not match.can_launch:
        return JSONResponse({"ok": False, "detail": "Launch not allowed"}, status_code=403)

    log_action(
        db,
        actor=user.email or user.username,
        action="app_launch",
        target=match.app.slug,
        details={
            "application_id": match.app.id,
            "app_slug": match.app.slug,
            "app_label": match.app.label,
            "access_level": match.access_level,
            "sources": match.sources,
            "grant_ids": match.grant_ids,
        },
        ip_address=_client_ip(request),
    )
    touch_app_session(db, user, match.app, _client_ip(request), request=request)
    return {"ok": True}


def _accessible_app_or_error(db: Session, user: UserContext, app_id: int):
    entries = get_effective_apps_for_user(
        db,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
    )
    return next((e for e in entries if e.app.id == app_id), None)


@router.post("/api/apps/{app_id}/favorite")
async def app_favorite_add(
    app_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_user_enriched),
):
    """Pin an accessible app into Accès rapides."""
    from app.web.portal_favorites import FavoriteError, add_favorite

    match = _accessible_app_or_error(db, user, app_id)
    if match is None:
        return JSONResponse({"ok": False, "detail": "App not accessible"}, status_code=404)
    try:
        created = add_favorite(
            db,
            keycloak_user_id=user.keycloak_user_id,
            application_id=app_id,
            actor=user.email or user.username or "user",
            ip_address=_client_ip(request),
        )
    except FavoriteError as exc:
        return JSONResponse({"ok": False, "detail": str(exc)}, status_code=400)
    return {"ok": True, "favorited": True, "created": created}


@router.delete("/api/apps/{app_id}/favorite")
async def app_favorite_remove(
    app_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_user_enriched),
):
    """Unpin an app from Accès rapides."""
    from app.web.portal_favorites import FavoriteError, remove_favorite

    match = _accessible_app_or_error(db, user, app_id)
    if match is None:
        return JSONResponse({"ok": False, "detail": "App not accessible"}, status_code=404)
    try:
        removed = remove_favorite(
            db,
            keycloak_user_id=user.keycloak_user_id,
            application_id=app_id,
            actor=user.email or user.username or "user",
            ip_address=_client_ip(request),
        )
    except FavoriteError as exc:
        return JSONResponse({"ok": False, "detail": str(exc)}, status_code=400)
    return {"ok": True, "favorited": False, "removed": removed}
