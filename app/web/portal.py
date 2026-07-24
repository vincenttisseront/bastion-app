"""End-user portal — application launcher (/apps) and profile (/profile)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.access_modes import app_launch_url
from app.audit import log_action
from app.database import get_db
from app.models import RealmConfig
from app.rbac.effective_access_service import get_effective_apps_for_user
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context
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
            db, entry.app, user.keycloak_user_id
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
    from app.web.portal_enrichment import PORTAL_FILTERS, recent_sessions_for_user

    apps_by_slug = {t["slug"]: t for t in tiles}
    recent = recent_sessions_for_user(db, user, apps_by_slug=apps_by_slug)
    return render(
        "portal/apps.html",
        **_portal_page_ctx(
            request,
            settings,
            user=user,
            portal_admin=portal_admin,
            apps=tiles,
            greeting_name=user.first_name,
            recent_sessions=recent,
            portal_filters=PORTAL_FILTERS,
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
        ),
    )


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
            "access_level": match.access_level,
            "sources": match.sources,
            "grant_ids": match.grant_ids,
        },
        ip_address=_client_ip(request),
    )
    touch_app_session(db, user, match.app, _client_ip(request), request=request)
    return {"ok": True}
