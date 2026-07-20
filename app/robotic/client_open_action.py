"""Client open action — GET /api/internal/impersonate/{slug}."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.robotic.impersonate_service import (
    ImpersonationError,
    get_basic_auth_header,
    impersonate,
)
from app.robotic.robotic_session_cookies import (
    build_crushftp_response_cookies,
    build_response_cookies,
)
from app.sso_settings import Settings, get_settings
from app.subdomain.subdomain_service import (
    get_app_allowed_groups,
    get_app_by_slug,
    user_has_access,
)
from app.testing_framework.throttle import throttle_retry_after_key
from app.web.user_context import UserContext, require_user

router = APIRouter(tags=["robotic"])


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "")


def _check_app_rbac(
    db: Session,
    slug: str,
    user: UserContext,
) -> JSONResponse | None:
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
    return None


def _impersonation_error_response(exc: ImpersonationError) -> JSONResponse:
    message = str(exc)
    status = 502
    if "No active credential" in message or "No credential" in message:
        status = 404
    elif "encryption" in message.lower() or "Fernet" in message or "PORTAL_SECRET" in message:
        status = 503
    elif "not found" in message.lower():
        status = 404
    elif "not configured" in message.lower() or "Basic Auth" in message:
        status = 400
    return JSONResponse({"ok": False, "error": message}, status_code=status)


@router.get("/api/internal/impersonate/{slug}")
async def client_impersonate(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user),
):
    denied = _check_app_rbac(db, slug, user)
    if denied is not None:
        return denied

    try:
        result = await impersonate(
            db,
            slug,
            settings,
            actor=user.email or user.username,
            ip_address=_client_ip(request),
        )
    except ImpersonationError as exc:
        return _impersonation_error_response(exc)

    response = RedirectResponse(url=result.target_url, status_code=302)
    if result.use_crushftp_cookies:
        build_crushftp_response_cookies(
            response,
            result.cookies,
            mode=result.mode,
            slug=result.slug,
            fqdn=result.fqdn,
        )
    else:
        build_response_cookies(
            response,
            result.cookies,
            mode=result.mode,
            slug=result.slug,
            fqdn=result.fqdn,
        )
    return response


@router.get("/internal/basic-auth-header/{slug}")
async def basic_auth_header(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user),
):
    """
    Nginx auth_request handler — returns X-Robotic-Authorization header only.

    Never called directly by browsers; consumed internally by Nginx.
    """
    throttle_key = f"basic_auth_header:{slug}:{user.email or user.username}"
    if wait := throttle_retry_after_key(throttle_key, min_interval_seconds=5):
        return Response(status_code=429, headers={"Retry-After": str(int(wait) + 1)})

    denied = _check_app_rbac(db, slug, user)
    if denied is not None:
        return Response(status_code=denied.status_code)

    try:
        result = await get_basic_auth_header(
            db,
            slug,
            settings,
            actor=user.email or user.username,
            ip_address=_client_ip(request),
        )
    except ImpersonationError:
        return Response(status_code=403)

    return Response(
        status_code=200,
        headers={"X-Robotic-Authorization": result.auth_header},
    )
