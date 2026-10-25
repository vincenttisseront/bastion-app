"""Admin MFA — TOTP + WebAuthn challenge and profile enrollment."""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth.mfa_cookie import clear_mfa_ok_cookie, set_mfa_ok_cookie
from app.auth.totp_service import (
    confirm_totp_enrollment,
    disable_totp,
    generate_new_totp_setup,
    mfa_status_dict,
    verify_login_totp,
)
from app.auth.webauthn_service import (
    WebAuthnError,
    build_authentication_options,
    build_registration_options,
    clear_challenge_cookie,
    disable_webauthn,
    pop_challenge,
    stash_challenge,
    verify_and_store_registration,
    verify_authentication,
)
from app.database import get_db
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.csrf import portal_signing_secret
from app.web.flash import base_template_context, flash_redirect
from app.web.templates import render
from app.secret_crypto import encryption_configured
from app.web.user_context import UserContext, require_admin_mfa_exempt

router = APIRouter(
    tags=["admin-mfa"],
    dependencies=[Depends(require_admin_mfa_exempt)],
)


def _ctx(request: Request, settings: Settings, **extra: Any) -> dict[str, Any]:
    return base_template_context(request, settings, APP_VERSION, **extra)


def _safe_next(raw: str | None) -> str:
    target = unquote((raw or "").strip()) or "/admin"
    if not target.startswith("/") or target.startswith("//"):
        return "/admin"
    if target.startswith("/admin/auth/mfa/"):
        return "/admin"
    return target


@router.get("/admin/auth/mfa/challenge")
def admin_mfa_challenge_get(
    request: Request,
    next: str = "/admin",
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_admin_mfa_exempt),
):
    status = mfa_status_dict(db, user.email)
    if not status.get("any_enabled"):
        return RedirectResponse(url="/admin/profile#mfa", status_code=303)
    return render(
        "admin/mfa_challenge.html",
        **_ctx(
            request,
            settings,
            hide_chrome=True,
            next_url=_safe_next(next),
            user=user,
            mfa=status,
        ),
    )


@router.post("/admin/auth/mfa/challenge")
def admin_mfa_challenge_post(
    request: Request,
    code: str = Form(""),
    next: str = Form("/admin"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_admin_mfa_exempt),
):
    dest = _safe_next(next)
    response = RedirectResponse(url=dest, status_code=303)
    if not verify_login_totp(db, settings, user.email, code):
        fail = RedirectResponse(
            url=f"/admin/auth/mfa/challenge?next={dest}",
            status_code=303,
        )
        flash_redirect(
            fail,
            "Code TOTP invalide ou expiré.",
            "error",
            portal_signing_secret(settings),
        )
        log_action(
            db,
            actor=user.email,
            action="admin.mfa_challenge_failed",
            target=user.email,
            details={},
        )
        return fail

    set_mfa_ok_cookie(response, settings, user.email)
    flash_redirect(
        response,
        "Second facteur validé.",
        "success",
        portal_signing_secret(settings),
    )
    log_action(
        db,
        actor=user.email,
        action="admin.mfa_challenge_ok",
        target=user.email,
        details={},
    )
    return response


@router.get("/admin/profile")
def admin_profile_get(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_admin_mfa_exempt),
):
    force_mfa = (request.query_params.get("force_mfa") or "").strip() in (
        "1",
        "true",
        "yes",
    )
    return render(
        "admin/profile.html",
        **_ctx(
            request,
            settings,
            user=user,
            mfa=mfa_status_dict(db, user.email),
            setup=None,
            force_mfa=force_mfa,
            encryption_ok=encryption_configured(settings),
        ),
    )


@router.post("/admin/profile/mfa/totp/start")
def admin_profile_totp_start(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_admin_mfa_exempt),
):
    response = RedirectResponse(url="/admin/profile#mfa", status_code=303)
    try:
        setup = generate_new_totp_setup(db, settings, user.email)
    except ValueError as exc:
        flash_redirect(
            response,
            str(exc),
            "error",
            portal_signing_secret(settings),
        )
        return response

    # Re-render with setup payload (one-shot; secret shown once).
    return render(
        "admin/profile.html",
        **_ctx(
            request,
            settings,
            user=user,
            mfa=mfa_status_dict(db, user.email),
            setup=setup,
            force_mfa=False,
            encryption_ok=True,
        ),
    )


@router.post("/admin/profile/mfa/totp/confirm")
def admin_profile_totp_confirm(
    request: Request,
    code: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_admin_mfa_exempt),
):
    response = RedirectResponse(url="/admin/profile#mfa", status_code=303)
    if not confirm_totp_enrollment(db, settings, user.email, code):
        flash_redirect(
            response,
            "Code invalide — rescannez le QR et réessayez.",
            "error",
            portal_signing_secret(settings),
        )
        return response
    set_mfa_ok_cookie(response, settings, user.email)
    flash_redirect(
        response,
        "TOTP activé pour votre compte admin.",
        "success",
        portal_signing_secret(settings),
    )
    log_action(
        db,
        actor=user.email,
        action="admin.mfa_totp_enabled",
        target=user.email,
        details={},
    )
    return response


@router.post("/admin/profile/mfa/totp/disable")
def admin_profile_totp_disable(
    request: Request,
    code: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_admin_mfa_exempt),
):
    response = RedirectResponse(url="/admin/profile#mfa", status_code=303)
    if not disable_totp(db, settings, user.email, code):
        flash_redirect(
            response,
            "Code TOTP invalide — désactivation annulée.",
            "error",
            portal_signing_secret(settings),
        )
        return response
    clear_mfa_ok_cookie(response)
    flash_redirect(
        response,
        "TOTP désactivé.",
        "success",
        portal_signing_secret(settings),
    )
    log_action(
        db,
        actor=user.email,
        action="admin.mfa_totp_disabled",
        target=user.email,
        details={},
    )
    return response


@router.post("/admin/profile/mfa/webauthn/options")
def admin_webauthn_register_options(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_admin_mfa_exempt),
):
    options, challenge = build_registration_options(settings, user.email)
    response = JSONResponse({"options": options})
    stash_challenge(
        response,
        settings,
        user_email=user.email,
        purpose="register",
        challenge=challenge,
    )
    return response


@router.post("/admin/profile/mfa/webauthn/verify")
async def admin_webauthn_register_verify(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_admin_mfa_exempt),
):
    body = await request.json()
    challenge = pop_challenge(
        request, settings, user_email=user.email, purpose="register"
    )
    if not challenge:
        return JSONResponse(
            {"ok": False, "error": "challenge_expired"}, status_code=400
        )
    try:
        verify_and_store_registration(
            db,
            settings,
            user_email=user.email,
            credential=body,
            expected_challenge=challenge,
        )
    except WebAuthnError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    response = JSONResponse(
        {"ok": True, "redirect": "/admin/profile#mfa"}
    )
    clear_challenge_cookie(response)
    set_mfa_ok_cookie(response, settings, user.email)
    log_action(
        db,
        actor=user.email,
        action="admin.mfa_webauthn_enabled",
        target=user.email,
        details={},
    )
    return response


@router.post("/admin/profile/mfa/webauthn/disable")
def admin_webauthn_disable(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_admin_mfa_exempt),
):
    response = RedirectResponse(url="/admin/profile#mfa", status_code=303)
    disable_webauthn(db, user.email)
    flash_redirect(
        response,
        "Passkey désactivé.",
        "success",
        portal_signing_secret(settings),
    )
    log_action(
        db,
        actor=user.email,
        action="admin.mfa_webauthn_disabled",
        target=user.email,
        details={},
    )
    return response


@router.post("/admin/auth/mfa/webauthn/options")
def admin_webauthn_auth_options(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_admin_mfa_exempt),
):
    try:
        options, challenge = build_authentication_options(
            db, settings, user.email
        )
    except WebAuthnError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    response = JSONResponse({"options": options})
    stash_challenge(
        response,
        settings,
        user_email=user.email,
        purpose="assert",
        challenge=challenge,
    )
    return response


@router.post("/admin/auth/mfa/webauthn/verify")
async def admin_webauthn_auth_verify(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_admin_mfa_exempt),
):
    body = await request.json()
    next_url = _safe_next(str(body.get("next") or "/admin"))
    challenge = pop_challenge(
        request, settings, user_email=user.email, purpose="assert"
    )
    if not challenge:
        return JSONResponse(
            {"ok": False, "error": "challenge_expired"}, status_code=400
        )
    try:
        verify_authentication(
            db,
            settings,
            user_email=user.email,
            credential=body.get("credential") or body,
            expected_challenge=challenge,
        )
    except WebAuthnError as exc:
        log_action(
            db,
            actor=user.email,
            action="admin.mfa_webauthn_failed",
            target=user.email,
            details={},
        )
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    response = JSONResponse({"ok": True, "redirect": next_url})
    clear_challenge_cookie(response)
    set_mfa_ok_cookie(response, settings, user.email)
    log_action(
        db,
        actor=user.email,
        action="admin.mfa_webauthn_ok",
        target=user.email,
        details={},
    )
    return response
