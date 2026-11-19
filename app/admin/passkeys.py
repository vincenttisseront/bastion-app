"""Admin view of end-user passkeys: list and revoke (lost / stolen device).

A passkey replaces password + OTP at sign-in, so an administrator must be able
to cut one — or all of a user's — without waiting for the user. Revocation is
soft (rows kept for audit) and immediate: ``verify_login_assertion`` only
matches non-revoked credentials.

Routes are behind ``require_admin`` (which also enforces admin MFA). Writes are
form posts with a CSRF token and a flash redirect back to the filtered list.
"""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.audit import admin_actor, log_action
from app.auth.passkey_service import (
    is_passkey_login_enabled_for_realm,
    list_active_passkeys,
    revoke_passkey,
    revoke_user_passkeys,
)
from app.database import get_db
from app.models import RealmConfig, UserPasskey
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.csrf import portal_signing_secret, verify_csrf_token
from app.web.flash import base_template_context, flash_redirect
from app.web.openapi_responses import RESP_404
from app.web.templates import render
from app.web.user_context import require_admin

router = APIRouter(tags=["admin-passkeys"], dependencies=[Depends(require_admin)])

PATH_ADMIN_PASSKEYS = "/admin/security/passkeys"
_TEMPLATE = "admin/passkeys.html"
_LIST_LIMIT = 500

_CSRF_INVALID = "Jeton CSRF invalide"
_AUDIT_REVOKED = "admin.passkey_revoked"
_AUDIT_REVOKED_ALL = "admin.passkeys_revoked_all"


def _optional_id(raw: str | None) -> int | None:
    """``realm_id`` from a form / query string: ``""`` (« Tous ») or junk → no filter."""
    text = (raw or "").strip()
    return int(text) if text.isdigit() else None


def _back(realm_id: int | None, q: str | None, sub: str | None) -> str:
    params = {k: v for k, v in (("realm_id", realm_id), ("q", q), ("sub", sub)) if v}
    return f"{PATH_ADMIN_PASSKEYS}?{urlencode(params)}" if params else PATH_ADMIN_PASSKEYS


def _row(pk: UserPasskey, realms: dict[int, RealmConfig]) -> dict:
    realm = realms.get(pk.realm_id)
    return {
        "id": pk.id,
        "realm_id": pk.realm_id,
        "realm_slug": realm.slug if realm else f"#{pk.realm_id}",
        "username": pk.username or "",
        "sub": pk.keycloak_sub,
        "name": pk.name or "Clé d'accès",
        "synced": bool(pk.backup_eligible),
        "created_at": pk.created_at,
        "last_used_at": pk.last_used_at,
        "last_used_ip": pk.last_used_ip or "",
    }


@router.get(PATH_ADMIN_PASSKEYS)
def admin_passkeys_list(
    request: Request,
    realm_id: str | None = Query(None, max_length=20),
    q: str | None = Query(None, max_length=200),
    sub: str | None = Query(None, max_length=200),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Active passkeys, filterable by realm / user (name, username or Keycloak id)."""
    realm_filter = _optional_id(realm_id)
    realms = {r.id: r for r in db.query(RealmConfig).order_by(RealmConfig.slug).all()}
    rows = list_active_passkeys(db, realm_id=realm_filter, sub=sub, search=q, limit=_LIST_LIMIT + 1)
    truncated = len(rows) > _LIST_LIMIT
    return render(
        _TEMPLATE,
        **base_template_context(
            request,
            settings,
            APP_VERSION,
            passkeys=[_row(pk, realms) for pk in rows[:_LIST_LIMIT]],
            truncated=truncated,
            realms=[
                {
                    "id": r.id,
                    "slug": r.slug,
                    "passkey_enabled": is_passkey_login_enabled_for_realm(db, r, settings),
                }
                for r in realms.values()
            ],
            filter_realm_id=realm_filter,
            filter_q=q or "",
            filter_sub=sub or "",
        ),
    )


@router.post(PATH_ADMIN_PASSKEYS + "/{passkey_id}/revoke", responses=RESP_404)
def admin_passkey_revoke(
    passkey_id: int,
    request: Request,
    csrf_token: str = Form(""),
    back_realm_id: str = Form("", max_length=20),
    back_q: str = Form(""),
    back_sub: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Revoke one passkey."""
    secret = portal_signing_secret(settings)
    response = RedirectResponse(
        url=_back(_optional_id(back_realm_id), back_q, back_sub), status_code=302
    )
    if not verify_csrf_token(request, secret, csrf_token):
        flash_redirect(response, _CSRF_INVALID, "error", secret)
        return response
    passkey = db.get(UserPasskey, passkey_id)
    if passkey is None or passkey.revoked:
        raise HTTPException(status_code=404, detail="Clé d'accès introuvable")
    actor = admin_actor(user)
    revoke_passkey(db, passkey, revoked_by=actor, reason="admin")
    db.commit()
    log_action(
        db,
        actor=actor,
        action=_AUDIT_REVOKED,
        target=f"passkey:{passkey.id}",
        details={
            "realm_id": passkey.realm_id,
            "sub": passkey.keycloak_sub,
            "username": passkey.username,
        },
        ip_address=client_ip_from_request(request) or None,
    )
    flash_redirect(response, "Clé d'accès révoquée.", "success", secret)
    return response


@router.post(PATH_ADMIN_PASSKEYS + "/revoke-user")
def admin_passkeys_revoke_user(
    request: Request,
    realm_id: int = Form(...),
    sub: str = Form(..., max_length=200),
    csrf_token: str = Form(""),
    back_realm_id: str = Form("", max_length=20),
    back_q: str = Form(""),
    back_sub: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Revoke every active passkey of one user in one realm."""
    secret = portal_signing_secret(settings)
    response = RedirectResponse(
        url=_back(_optional_id(back_realm_id), back_q, back_sub), status_code=302
    )
    if not verify_csrf_token(request, secret, csrf_token):
        flash_redirect(response, _CSRF_INVALID, "error", secret)
        return response
    actor = admin_actor(user)
    count = revoke_user_passkeys(db, sub=sub, realm_id=realm_id, revoked_by=actor, reason="admin")
    db.commit()
    if count:
        log_action(
            db,
            actor=actor,
            action=_AUDIT_REVOKED_ALL,
            target=f"user:{sub.strip()}",
            details={"realm_id": realm_id, "sub": sub.strip(), "count": count},
            ip_address=client_ip_from_request(request) or None,
        )
    flash_redirect(
        response,
        f"{count} clé(s) d'accès révoquée(s)." if count else "Aucune clé d'accès active.",
        "success" if count else "info",
        secret,
    )
    return response
