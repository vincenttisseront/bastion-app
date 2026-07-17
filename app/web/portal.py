"""End-user portal — application launcher home (/apps)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.access_modes import app_launch_url
from app.audit import log_action
from app.database import get_db
from app.rbac.effective_access_service import get_effective_apps_for_user
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context
from app.web.templates import render
from app.web.user_context import UserContext, is_portal_admin, require_user

router = APIRouter(tags=["portal"])


def _ctx(request: Request, settings: Settings, **extra):
    return base_template_context(request, settings, APP_VERSION, **extra)


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "")


def _effective_tiles(db: Session, user: UserContext) -> list[dict]:
    entries = get_effective_apps_for_user(
        db,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
    )
    tiles: list[dict] = []
    for entry in entries:
        tiles.append(
            {
                "id": entry.app.id,
                "slug": entry.app.slug,
                "label": entry.app.label,
                "access_mode": entry.app.access_mode,
                "access_level": entry.access_level,
                "can_launch": entry.can_launch,
                "launch_url": app_launch_url(entry.app),
                "sources": entry.sources,
                "tile_icon": entry.app.tile_icon,
            }
        )
    return tiles


@router.get("/apps")
def apps_portal(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user),
):
    """User home: grid of applications the caller may access."""
    if user.is_breakglass:
        return RedirectResponse(url="/dashboard", status_code=302)

    portal_admin = is_portal_admin(user, db, settings)
    tiles = _effective_tiles(db, user)
    return render(
        "portal/apps.html",
        **_ctx(
            request,
            settings,
            hide_chrome=True,
            apps=tiles,
            is_portal_admin=portal_admin,
            portal_user=user,
        ),
    )


@router.post("/api/apps/{app_id}/launch-ping")
def app_launch_ping(
    app_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_user),
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
    return {"ok": True}
