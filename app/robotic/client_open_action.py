"""Client open action — GET /api/internal/impersonate/{slug}."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.robotic.impersonate_service import ImpersonationError, impersonate
from app.robotic.robotic_session_cookies import build_response_cookies
from app.sso_settings import Settings, get_settings
from app.subdomain.subdomain_service import (
    get_app_allowed_groups,
    get_app_by_slug,
    user_has_access,
)
from app.web.user_context import UserContext, require_user

router = APIRouter(prefix="/api/internal", tags=["robotic"])


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "")


@router.get("/impersonate/{slug}")
async def client_impersonate(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user),
):
    app = get_app_by_slug(db, slug)
    if app is None:
        return JSONResponse({"detail": f"App '{slug}' not found"}, status_code=404)

    if not user.is_admin:
        app_groups = get_app_allowed_groups(db, app.id)
        if not user_has_access(user.groups, app_groups):
            return JSONResponse(
                {"detail": "Access denied to this application"},
                status_code=403,
            )

    try:
        result = await impersonate(
            db,
            slug,
            settings,
            actor=user.email or user.username,
            ip_address=_client_ip(request),
        )
    except ImpersonationError as exc:
        message = str(exc)
        status = 502
        if "No active credential" in message or "No credential" in message:
            status = 404
        elif "encryption" in message.lower() or "Fernet" in message or "PORTAL_SECRET" in message:
            status = 503
        elif "not found" in message.lower():
            status = 404
        elif "not configured for CrushFTP" in message:
            status = 400
        return JSONResponse(
            {"ok": False, "error": message},
            status_code=status,
        )

    response = RedirectResponse(url=result.target_url, status_code=302)
    build_response_cookies(
        response,
        result.cookies,
        mode=result.mode,
        slug=result.slug,
        fqdn=result.fqdn,
    )
    return response
