"""Client open action — GET /api/internal/impersonate/{slug} + identity POST."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.admin.throttling import (
    check_identity_attempt_block,
    clear_identity_failures,
    record_identity_failure,
)
from app.audit import log_action
from app.bastion.bastion_fields import (
    normalize_credential_mode,
    resolve_identity_login_username,
)
from app.database import get_db
from app.request_client_ip import client_ip_from_request
from app.robotic.impersonate_service import (
    ImpersonationCredentialRequiredError,
    ImpersonationError,
    ImpersonationIdentityAuthError,
    ImpersonationPasswordRequiredError,
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
from app.web.sessions_service import app_cookie_diagnostics, touch_app_session
from app.web.user_context import UserContext, require_user

router = APIRouter(tags=["robotic"])


class OpenWithIdentityBody(BaseModel):
    """Password only — username always comes from the OIDC session server-side."""

    password: str = Field(min_length=1)
    # Ignored if present — never trusted for identity mode.
    username: str | None = None


def _client_ip(request: Request) -> str:
    return client_ip_from_request(request)


def _oidc_login_username(user: UserContext, identity_format: str | None = "email") -> str:
    """OIDC session → LDAPS/robotic login (default: full email/UPN like sessions)."""
    return resolve_identity_login_username(
        email=user.email,
        username=user.username,
        identity_format=identity_format,
    )


def _identity_user_key(user: UserContext) -> str:
    return user.keycloak_user_id or user.email or user.username or "unknown"


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
    if isinstance(exc, ImpersonationCredentialRequiredError):
        return JSONResponse(
            {
                "error": ImpersonationCredentialRequiredError.error_code,
                "message": ImpersonationCredentialRequiredError.user_message,
            },
            status_code=409,
        )
    if isinstance(exc, ImpersonationPasswordRequiredError):
        return JSONResponse(
            {
                "error": ImpersonationPasswordRequiredError.error_code,
                "message": ImpersonationPasswordRequiredError.user_message,
            },
            status_code=400,
        )
    if isinstance(exc, ImpersonationIdentityAuthError):
        # 403 — not 401. Nginx has proxy_intercept_errors on + error_page 401 →
        # /auth/login; a 401 here would look like a dead SSO session to the browser.
        return JSONResponse(
            {
                "error": ImpersonationIdentityAuthError.error_code,
                "message": ImpersonationIdentityAuthError.user_message,
            },
            status_code=403,
        )
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


def _touch_open_session(
    result,
    *,
    settings: Settings,
    db: Session,
    user: UserContext,
    request: Request,
    slug: str,
) -> None:
    app = get_app_by_slug(db, slug)
    if app is None:
        return
    touch_app_session(
        db,
        user,
        app,
        _client_ip(request),
        details=app_cookie_diagnostics(
            result.cookies,
            credential_source=result.credential_source,
            robotic_username=result.robotic_username,
            driver=result.driver,
            request=request,
            app_label=app.label,
            verify_base_url=result.login_base_url,
        ),
    )


def _attach_robotic_cookies(response: Response, result, *, settings: Settings) -> None:
    if result.use_crushftp_cookies:
        build_crushftp_response_cookies(
            response,
            result.cookies,
            mode=result.mode,
            slug=result.slug,
            fqdn=result.fqdn,
            portal_domain=settings.portal_domain,
        )
    else:
        build_response_cookies(
            response,
            result.cookies,
            mode=result.mode,
            slug=result.slug,
            fqdn=result.fqdn,
            portal_domain=settings.portal_domain,
        )


def _cookie_redirect(
    result,
    *,
    settings: Settings,
    db: Session,
    user: UserContext,
    request: Request,
    slug: str,
) -> RedirectResponse:
    _touch_open_session(
        result, settings=settings, db=db, user=user, request=request, slug=slug
    )
    response = RedirectResponse(url=result.target_url, status_code=302)
    _attach_robotic_cookies(response, result, settings=settings)
    return response


def _cookie_json_open(
    result,
    *,
    settings: Settings,
    db: Session,
    user: UserContext,
    request: Request,
    slug: str,
) -> JSONResponse:
    """JSON success for fetch clients — Set-Cookie + target_url (no 302 fallback to href)."""
    _touch_open_session(
        result, settings=settings, db=db, user=user, request=request, slug=slug
    )
    response = JSONResponse(
        {
            "ok": True,
            "target_url": result.target_url,
            "slug": result.slug,
        }
    )
    _attach_robotic_cookies(response, result, settings=settings)
    return response


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

    app = get_app_by_slug(db, slug)
    if app is not None and normalize_credential_mode(app.credential_mode) == "identite_utilisateur":
        return JSONResponse(
            {
                "error": ImpersonationPasswordRequiredError.error_code,
                "message": ImpersonationPasswordRequiredError.user_message,
            },
            status_code=400,
        )

    try:
        result = await impersonate(
            db,
            slug,
            settings,
            actor=user.email or user.username,
            ip_address=_client_ip(request),
            keycloak_user_id=user.keycloak_user_id,
        )
    except ImpersonationError as exc:
        return _impersonation_error_response(exc)

    return _cookie_redirect(
        result, settings=settings, db=db, user=user, request=request, slug=slug
    )


@router.post("/api/apps/{slug}/open-with-identity")
async def open_with_identity(
    slug: str,
    body: OpenWithIdentityBody,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user),
):
    """
    Open an app in identite_utilisateur mode.

    Username is taken exclusively from the OIDC session (never from the body).
    Password is used once for the robotic login then discarded — never logged.
    """
    denied = _check_app_rbac(db, slug, user)
    if denied is not None:
        return denied

    app = get_app_by_slug(db, slug)
    if app is None or not app.enabled:
        return JSONResponse({"detail": f"App '{slug}' not found"}, status_code=404)
    if normalize_credential_mode(app.credential_mode) != "identite_utilisateur":
        return JSONResponse(
            {"detail": "This application is not configured for identity password mode"},
            status_code=400,
        )

    user_key = _identity_user_key(user)
    if wait := check_identity_attempt_block(slug, user_key):
        log_action(
            db,
            actor=user.email or user.username,
            action="robotic.impersonate.blocked_identity",
            target=f"app:{slug}",
            details={
                "app_slug": slug,
                "success": False,
                "reason": "too_many_failed_identity_attempts",
                "credential_mode": "identite_utilisateur",
            },
            ip_address=_client_ip(request),
        )
        return JSONResponse(
            {
                "error": "too_many_attempts",
                "message": (
                    "Trop de tentatives échouées. Réessayez dans quelques minutes."
                ),
                "retry_after": int(wait) + 1,
            },
            status_code=429,
            headers={"Retry-After": str(int(wait) + 1)},
        )

    username = _oidc_login_username(user, getattr(app, "identity_format", None))
    if not username:
        return JSONResponse(
            {
                "error": "identity_unavailable",
                "message": "Identité utilisateur indisponible. Reconnectez-vous au portail.",
            },
            status_code=400,
        )

    password = body.password
    # body.username is intentionally ignored (never trusted).
    try:
        result = await impersonate(
            db,
            slug,
            settings,
            actor=user.email or user.username,
            ip_address=_client_ip(request),
            keycloak_user_id=user.keycloak_user_id,
            ephemeral_username=username,
            ephemeral_password=password,
        )
    except ImpersonationError as exc:
        record_identity_failure(slug, user_key)
        return _impersonation_error_response(exc)
    finally:
        password = ""  # noqa: F841
        body.password = ""  # noqa: F841

    clear_identity_failures(slug, user_key)
    # Always JSON for the catalogue modal fetch — never 302 (browsers hide Location
    # on opaque redirects and the UI used to fall back to the tile impersonate href).
    return _cookie_json_open(
        result, settings=settings, db=db, user=user, request=request, slug=slug
    )


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
            keycloak_user_id=user.keycloak_user_id,
        )
    except ImpersonationCredentialRequiredError:
        return Response(status_code=409)
    except ImpersonationError:
        return Response(status_code=403)

    return Response(
        status_code=200,
        headers={"X-Robotic-Authorization": result.auth_header},
    )
