"""Client open action — GET /api/internal/impersonate/{slug} + identity POST."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
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
    ImpersonationTechnicalError,
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
from app.web.flash import flash_redirect
from app.web.sessions_service import app_cookie_diagnostics, touch_app_session
from app.web.user_context import UserContext, require_user_enriched

router = APIRouter(tags=["robotic"], dependencies=[Depends(require_user_enriched)])

_APPS_CATALOGUE = "/apps"


def _client_ip(request: Request) -> str:
    return client_ip_from_request(request)


def _browser_fingerprint_headers(request: Request) -> dict[str, str]:
    """Forward UA / Accept-Language so upstream BrowserFingerprint matches the user."""
    out: dict[str, str] = {}
    ua = request.headers.get("user-agent")
    if ua:
        out["user-agent"] = ua
    lang = request.headers.get("accept-language")
    if lang:
        out["accept-language"] = lang
    return out


def _oidc_login_username(
    user: UserContext,
    identity_format: str | None = "email",
    *,
    email: str | None = None,
) -> str:
    """OIDC session → LDAPS/robotic login (default: full email/UPN like sessions)."""
    return resolve_identity_login_username(
        email=email if email is not None else user.email,
        username=user.username,
        identity_format=identity_format,
    )


def _identity_user_key(user: UserContext) -> str:
    return user.keycloak_user_id or user.email or user.username or "unknown"


def _wants_json(request: Request) -> bool:
    """True for API/JSON clients; False for HTML form top-level navigations."""
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        return True
    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept and "text/html" not in accept:
        return True
    return False


def _flash_secret(settings: Settings) -> str:
    return settings.vault_portal_internal_token or "dev"


async def _read_identity_password(request: Request) -> str:
    """Password from form POST (preferred) or JSON body — never logged."""
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        try:
            payload = await request.json()
        except Exception:
            return ""
        if isinstance(payload, dict):
            return str(payload.get("password") or "")
        return ""
    form = await request.form()
    return str(form.get("password") or "")


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


def _impersonation_error_payload(exc: ImpersonationError) -> tuple[dict, int]:
    if isinstance(exc, ImpersonationCredentialRequiredError):
        return (
            {
                "error": ImpersonationCredentialRequiredError.error_code,
                "message": ImpersonationCredentialRequiredError.user_message,
            },
            409,
        )
    if isinstance(exc, ImpersonationPasswordRequiredError):
        return (
            {
                "error": ImpersonationPasswordRequiredError.error_code,
                "message": ImpersonationPasswordRequiredError.user_message,
            },
            400,
        )
    if isinstance(exc, ImpersonationIdentityAuthError):
        return (
            {
                "error": ImpersonationIdentityAuthError.error_code,
                "message": ImpersonationIdentityAuthError.user_message,
            },
            403,
        )
    if isinstance(exc, ImpersonationTechnicalError):
        return (
            {
                "error": ImpersonationTechnicalError.error_code,
                "message": ImpersonationTechnicalError.user_message,
            },
            502,
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
    return {"ok": False, "error": message}, status


def _impersonation_error_response(exc: ImpersonationError) -> JSONResponse:
    payload, status = _impersonation_error_payload(exc)
    return JSONResponse(payload, status_code=status)


def _identity_error_redirect(
    *,
    settings: Settings,
    message: str,
) -> RedirectResponse:
    """Top-level form POSTs cannot consume JSON — flash + return to catalogue."""
    response = RedirectResponse(url=_APPS_CATALOGUE, status_code=303)
    flash_redirect(response, message, "error", _flash_secret(settings))
    return response


def _identity_error_response(
    request: Request,
    *,
    settings: Settings,
    message: str,
    json_payload: dict | None = None,
    json_status: int = 400,
) -> Response:
    if _wants_json(request):
        return JSONResponse(
            json_payload or {"error": "error", "message": message},
            status_code=json_status,
        )
    return _identity_error_redirect(settings=settings, message=message)


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
    status_code: int = 302,
) -> RedirectResponse:
    _touch_open_session(
        result, settings=settings, db=db, user=user, request=request, slug=slug
    )
    response = RedirectResponse(url=result.target_url, status_code=status_code)
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
    """JSON success for API clients — Set-Cookie + target_url."""
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
    user: UserContext = Depends(require_user_enriched),
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
            client_headers=_browser_fingerprint_headers(request),
        )
    except ImpersonationError as exc:
        return _impersonation_error_response(exc)

    return _cookie_redirect(
        result, settings=settings, db=db, user=user, request=request, slug=slug
    )


@router.post("/api/apps/{slug}/open-with-identity")
async def open_with_identity(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    """
    Open an app in identite_utilisateur mode.

    Prefer a real HTML form POST (top-level navigation): browsers honor
    Set-Cookie Domain=parent only on document navigations, not fetch/XHR.
    Success → 303 + Set-Cookie + Location. Errors → flash + 303 /apps
    (JSON only when the client posts application/json).
    """
    wants_json = _wants_json(request)

    denied = _check_app_rbac(db, slug, user)
    if denied is not None:
        if wants_json:
            return denied
        detail = "Accès refusé à cette application."
        try:
            if denied.body:
                detail = json.loads(denied.body).get("detail") or detail
        except Exception:
            pass
        return _identity_error_redirect(settings=settings, message=str(detail))

    app = get_app_by_slug(db, slug)
    if app is None or not app.enabled:
        return _identity_error_response(
            request,
            settings=settings,
            message="Application introuvable.",
            json_payload={"detail": f"App '{slug}' not found"},
            json_status=404,
        )
    if normalize_credential_mode(app.credential_mode) != "identite_utilisateur":
        return _identity_error_response(
            request,
            settings=settings,
            message="Cette application n'accepte pas ce mode d'ouverture.",
            json_payload={
                "detail": "This application is not configured for identity password mode"
            },
            json_status=400,
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
        message = "Trop de tentatives échouées. Réessayez dans quelques minutes."
        if wants_json:
            return JSONResponse(
                {
                    "error": "too_many_attempts",
                    "message": message,
                    "retry_after": int(wait) + 1,
                },
                status_code=429,
                headers={"Retry-After": str(int(wait) + 1)},
            )
        return _identity_error_redirect(settings=settings, message=message)

    username = _oidc_login_username(user, getattr(app, "identity_format", None))
    if not username:
        message = "Identité utilisateur indisponible. Reconnectez-vous au portail."
        return _identity_error_response(
            request,
            settings=settings,
            message=message,
            json_payload={"error": "identity_unavailable", "message": message},
            json_status=400,
        )

    password = await _read_identity_password(request)
    if not password:
        message = "Mot de passe requis."
        return _identity_error_response(
            request,
            settings=settings,
            message=message,
            json_payload={"error": "password_required", "message": message},
            json_status=400,
        )

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
            client_headers=_browser_fingerprint_headers(request),
        )
    except ImpersonationTechnicalError as exc:
        payload, status = _impersonation_error_payload(exc)
        return _identity_error_response(
            request,
            settings=settings,
            message=payload.get("message") or ImpersonationTechnicalError.user_message,
            json_payload=payload,
            json_status=status,
        )
    except ImpersonationError as exc:
        record_identity_failure(slug, user_key)
        payload, status = _impersonation_error_payload(exc)
        return _identity_error_response(
            request,
            settings=settings,
            message=payload.get("message") or str(exc),
            json_payload=payload,
            json_status=status,
        )
    finally:
        password = ""  # noqa: F841

    clear_identity_failures(slug, user_key)

    # Top-level navigation (form POST) — 303 so Domain=parent is honored by browsers.
    # JSON clients keep the previous contract for automated tests/API callers.
    if wants_json:
        return _cookie_json_open(
            result, settings=settings, db=db, user=user, request=request, slug=slug
        )
    return _cookie_redirect(
        result,
        settings=settings,
        db=db,
        user=user,
        request=request,
        slug=slug,
        status_code=303,
    )


@router.get("/internal/basic-auth-header/{slug}")
async def basic_auth_header(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
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
