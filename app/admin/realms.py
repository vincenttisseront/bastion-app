"""Admin HTML/JSON routes for OIDC realm configuration."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.admin.export import (
    compute_redirect_uri,
    export_realm_files,
    persist_test_result,
    purge_realm_exports_after_delete,
)
from app.admin.oidc_test import test_oidc_connection
from app.admin.ports import NoAvailablePortError, get_next_available_port, test_port_available
from app.admin.schemas import (
    RealmConfigCreate,
    RealmConfigUpdate,
    PortTestBody,
    RealmTestBody,
    validation_errors_response,
)
from app.testing_framework.throttle import throttle_retry_after
from app.audit import log_action
from app.database import get_db
from app.models import RealmConfig
from app.secret_crypto import decrypt_secret, encrypt_secret, encryption_config_error, encryption_configured
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context, flash_redirect
from app.web.templates import render
from app.web.user_context import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-realms"], dependencies=[Depends(require_admin)])


def _port_collision_message(new_port: int) -> str:
    return (
        "Le port choisi vient d'être pris par une autre configuration. "
        f"Un nouveau port a été proposé : {new_port}."
    )


def _is_oauth2_proxy_port_integrity_error(exc: IntegrityError) -> bool:
    """Detect unique constraint failures on oauth2_proxy_port across SQLite/Postgres."""
    msg = str(getattr(exc, "orig", None) or exc).lower()
    return "oauth2_proxy_port" in msg


def _ctx(request: Request, settings: Settings, **extra: Any) -> dict[str, Any]:
    return base_template_context(request, settings, APP_VERSION, **extra)


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "")


def _wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "application/json" in accept or request.headers.get("x-requested-with") == "XMLHttpRequest"


def _form_bool(value: str | None) -> bool:
    return value in ("on", "true", "1", "yes")


def _check_slug_unique(db: Session, slug: str, exclude_id: int | None = None) -> str | None:
    query = db.query(RealmConfig).filter_by(slug=slug)
    if exclude_id is not None:
        query = query.filter(RealmConfig.id != exclude_id)
    if query.first():
        return "Ce slug existe déjà"
    return None


def _check_port_unique(
    db: Session, port: int, exclude_id: int | None = None
) -> str | None:
    query = db.query(RealmConfig).filter_by(oauth2_proxy_port=port)
    if exclude_id is not None:
        query = query.filter(RealmConfig.id != exclude_id)
    if query.first():
        return "Port déjà utilisé par un autre realm"
    return None


def _resolve_client_secret(
    provided: str | None, realm: RealmConfig | None, settings: Settings
) -> str | None:
    if provided and provided.strip():
        return provided.strip()
    if realm and realm.client_secret_encrypted:
        try:
            return decrypt_secret(realm.client_secret_encrypted, settings)
        except ValueError:
            return None
    return None


def _resolve_admin_client_secret(
    provided: str | None, realm: RealmConfig | None, settings: Settings
) -> str | None:
    if provided and provided.strip():
        return provided.strip()
    if realm and realm.keycloak_admin_client_secret_encrypted:
        try:
            return decrypt_secret(realm.keycloak_admin_client_secret_encrypted, settings)
        except ValueError:
            return None
    return None


def _realm_form_values(
  realm: RealmConfig | None,
  *,
  slug: str = "",
  name: str = "",
  issuer_url: str = "",
  client_id: str = "",
  oauth2_proxy_port: int | str = "",
  scopes: str = "openid profile email",
  is_default: bool = False,
) -> dict[str, Any]:
    if realm:
        return {
            "slug": realm.slug,
            "name": realm.name,
            "issuer_url": realm.issuer_url,
            "client_id": realm.client_id,
            "oauth2_proxy_port": realm.oauth2_proxy_port,
            "scopes": realm.scopes,
            "is_default": realm.is_default,
            "redirect_uri": realm.redirect_uri,
            "last_test_status": realm.last_test_status,
            "last_tested_at": realm.last_tested_at,
            "enabled": realm.enabled,
            "keycloak_admin_client_id": realm.keycloak_admin_client_id or "",
            "groups_sync_enabled": bool(realm.groups_sync_enabled),
            "keycloak_provision_client_id": realm.keycloak_provision_client_id or "",
            "provisioning_configured": bool(realm.keycloak_provision_client_secret_encrypted),
            "provisioning_enabled": bool(realm.provisioning_enabled),
        }
    return {
        "slug": slug,
        "name": name,
        "issuer_url": issuer_url,
        "client_id": client_id,
        "oauth2_proxy_port": oauth2_proxy_port,
        "scopes": scopes or "openid profile email",
        "is_default": is_default,
        "redirect_uri": "",
        "last_test_status": None,
        "last_tested_at": None,
        "enabled": False,
        "keycloak_admin_client_id": "",
        "groups_sync_enabled": False,
        "keycloak_provision_client_id": "",
        "provisioning_configured": False,
        "provisioning_enabled": False,
    }


def _apply_default_realm(db: Session, realm: RealmConfig, is_default: bool) -> None:
    if is_default:
        db.query(RealmConfig).filter(
            RealmConfig.id != realm.id, RealmConfig.is_default.is_(True)
        ).update({"is_default": False})
    realm.is_default = is_default


def _guard_activation(realm: RealmConfig, enabled: bool) -> str | None:
    if enabled and realm.last_test_status != "ok":
        return "Impossible d'activer un realm dont le test de connexion n'a pas réussi"
    return None


def _guard_encryption(settings: Settings) -> str | None:
    if not encryption_configured(settings):
        return encryption_config_error()
    return None


def _safe_encrypt_secret(plaintext: str, settings: Settings) -> tuple[str | None, str | None]:
    try:
        return encrypt_secret(plaintext, settings), None
    except ValueError as exc:
        return None, str(exc)


@router.get("/admin/realms")
def admin_realms_list(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    schema_error: str | None = None
    try:
        realms = db.query(RealmConfig).order_by(RealmConfig.slug).all()
    except SQLAlchemyError:
        logger.exception("Realm list query failed — schema migration likely pending")
        realms = []
        schema_error = (
            "Schéma base de données incompatible. Sur le serveur : "
            "cd /opt/sso-portal && alembic upgrade head"
        )
    encryption_error = _guard_encryption(settings)
    return render(
        "admin/realms_list.html",
        **_ctx(
            request,
            settings,
            realms=realms,
            schema_error=schema_error,
            encryption_error=encryption_error,
        ),
    )


@router.get("/admin/realms/session-alignment")
async def admin_realms_session_alignment(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    """Compare oauth2-proxy cookie TTL (export) vs Keycloak ssoSessionMaxLifespan."""
    from app.admin.session_alignment import (
        TARGET_COOKIE_EXPIRE,
        TARGET_COOKIE_HTTPONLY,
        TARGET_COOKIE_REFRESH,
        TARGET_COOKIE_SAMESITE,
        TARGET_COOKIE_SECURE,
        build_session_alignment_report,
    )

    rows = await build_session_alignment_report(db, settings)
    return render(
        "admin/realms_session_alignment.html",
        **_ctx(
            request,
            settings,
            rows=rows,
            target_cookie_expire=TARGET_COOKIE_EXPIRE,
            target_cookie_refresh=TARGET_COOKIE_REFRESH,
            target_cookie_secure=TARGET_COOKIE_SECURE,
            target_cookie_httponly=TARGET_COOKIE_HTTPONLY,
            target_cookie_samesite=TARGET_COOKIE_SAMESITE,
            all_coherent=all(r.coherent for r in rows) if rows else False,
        ),
    )


@router.get("/api/admin/realms/session-alignment")
async def api_realms_session_alignment(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    from app.admin.session_alignment import (
        TARGET_COOKIE_EXPIRE,
        TARGET_COOKIE_HTTPONLY,
        TARGET_COOKIE_REFRESH,
        TARGET_COOKIE_SAMESITE,
        TARGET_COOKIE_SECURE,
        build_session_alignment_report,
    )

    rows = await build_session_alignment_report(db, settings)
    return JSONResponse(
        {
            "ok": True,
            "target": {
                "cookie_expire": TARGET_COOKIE_EXPIRE,
                "cookie_refresh": TARGET_COOKIE_REFRESH,
                "cookie_secure": TARGET_COOKIE_SECURE,
                "cookie_httponly": TARGET_COOKIE_HTTPONLY,
                "cookie_samesite": TARGET_COOKIE_SAMESITE,
                "sso_session_max_lifespan_max_s": 12 * 3600,
            },
            "realms": [r.to_dict() for r in rows],
            "all_coherent": all(r.coherent for r in rows) if rows else False,
        }
    )


@router.get("/admin/realms/new")
def admin_realms_new(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    suggested_port: int | str = ""
    try:
        suggested_port = get_next_available_port(db, settings)
    except NoAvailablePortError:
        suggested_port = ""
    return render(
        "admin/realm_form.html",
        **_ctx(
            request,
            settings,
            realm=None,
            form_values=_realm_form_values(None, oauth2_proxy_port=suggested_port or ""),
            errors={},
            encryption_error=_guard_encryption(settings),
        ),
    )


@router.post("/admin/realms")
async def admin_realms_create(
    request: Request,
    slug: str = Form(""),
    name: str = Form(""),
    issuer_url: str = Form(""),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    keycloak_admin_client_id: str = Form(""),
    keycloak_admin_client_secret: str = Form(""),
    keycloak_provision_client_id: str = Form(""),
    keycloak_provision_client_secret: str = Form(""),
    provisioning_enabled: str | None = Form(None),
    oauth2_proxy_port: int = Form(4180),
    scopes: str = Form("openid profile email"),
    is_default: str | None = Form(None),
    activate: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    form_values = _realm_form_values(
        None,
        slug=slug,
        name=name,
        issuer_url=issuer_url,
        client_id=client_id,
        oauth2_proxy_port=oauth2_proxy_port,
        scopes=scopes,
        is_default=_form_bool(is_default),
    )
    form_values["keycloak_provision_client_id"] = keycloak_provision_client_id
    form_values["provisioning_enabled"] = _form_bool(provisioning_enabled)
    enabled = _form_bool(activate)

    try:
        data = RealmConfigCreate(
            slug=slug,
            name=name,
            issuer_url=issuer_url,
            client_id=client_id,
            client_secret=client_secret,
            keycloak_admin_client_id=keycloak_admin_client_id or None,
            keycloak_admin_client_secret=keycloak_admin_client_secret or None,
            keycloak_provision_client_id=keycloak_provision_client_id or None,
            keycloak_provision_client_secret=keycloak_provision_client_secret or None,
            provisioning_enabled=_form_bool(provisioning_enabled),
            oauth2_proxy_port=oauth2_proxy_port,
            scopes=scopes,
            is_default=_form_bool(is_default),
            enabled=enabled,
        )
    except ValidationError as exc:
        errors = validation_errors_response(exc)["errors"]
        if _wants_json(request):
            return JSONResponse({"ok": False, "errors": errors}, status_code=400)
        return render(
            "admin/realm_form.html",
            **_ctx(request, settings, realm=None, form_values=form_values, errors=errors),
            status_code=400,
        )

    errors: dict[str, str] = {}
    if enc_err := _guard_encryption(settings):
        errors["_form"] = enc_err
    if slug_err := _check_slug_unique(db, data.slug):
        errors["slug"] = slug_err
    if port_err := _check_port_unique(db, data.oauth2_proxy_port):
        errors["oauth2_proxy_port"] = port_err
    if enabled:
        test_result = await test_oidc_connection(
            data.issuer_url, data.client_id, data.client_secret
        )
        if test_result["status"] != "ok":
            errors["_form"] = "Le test de connexion doit réussir avant l'activation"
    if errors:
        if _wants_json(request):
            return JSONResponse({"ok": False, "errors": errors}, status_code=400)
        return render(
            "admin/realm_form.html",
            **_ctx(request, settings, realm=None, form_values=form_values, errors=errors),
            status_code=400,
        )

    redirect_uri = compute_redirect_uri(data.slug, settings)
    encrypted_secret, enc_err = _safe_encrypt_secret(data.client_secret, settings)
    if enc_err:
        errors["_form"] = enc_err
        return render(
            "admin/realm_form.html",
            **_ctx(request, settings, realm=None, form_values=form_values, errors=errors),
            status_code=400,
        )

    admin_client_id: str | None = (data.keycloak_admin_client_id or "").strip() or None
    admin_secret_plain: str | None = (data.keycloak_admin_client_secret or "").strip() or None
    admin_secret_encrypted: str | None = None
    if admin_client_id or admin_secret_plain:
        if not admin_client_id:
            errors["keycloak_admin_client_id"] = "Client ID requis"
        if not admin_secret_plain:
            errors["keycloak_admin_client_secret"] = "Client secret requis"
        if errors:
            if _wants_json(request):
                return JSONResponse({"ok": False, "errors": errors}, status_code=400)
            return render(
                "admin/realm_form.html",
                **_ctx(request, settings, realm=None, form_values=form_values, errors=errors),
                status_code=400,
            )
        admin_secret_encrypted, enc_err = _safe_encrypt_secret(admin_secret_plain, settings)
        if enc_err:
            errors["_form"] = enc_err
            return render(
                "admin/realm_form.html",
                **_ctx(request, settings, realm=None, form_values=form_values, errors=errors),
                status_code=400,
            )

    provision_client_id: str | None = data.keycloak_provision_client_id
    provision_secret_plain: str | None = data.keycloak_provision_client_secret
    provision_secret_encrypted: str | None = None
    if provision_client_id or provision_secret_plain:
        if not provision_client_id:
            errors["keycloak_provision_client_id"] = "Client ID requis"
        if not provision_secret_plain:
            errors["keycloak_provision_client_secret"] = "Client secret requis"
        if not errors:
            provision_secret_encrypted, enc_err = _safe_encrypt_secret(
                provision_secret_plain, settings
            )
            if enc_err:
                errors["_form"] = enc_err
    # Opt-in EXPLICITE : jamais auto-dérivé de la présence des identifiants
    # (contrairement à groups_sync_enabled — écriture Keycloak = case consciente).
    provisioning_opt_in = data.provisioning_enabled
    if provisioning_opt_in and not (provision_client_id and provision_secret_encrypted):
        errors["provisioning_enabled"] = (
            "Renseignez le compte de service provisioning avant d'activer le provisioning"
        )
    if errors:
        if _wants_json(request):
            return JSONResponse({"ok": False, "errors": errors}, status_code=400)
        return render(
            "admin/realm_form.html",
            **_ctx(request, settings, realm=None, form_values=form_values, errors=errors),
            status_code=400,
        )

    realm = RealmConfig(
        slug=data.slug,
        name=data.name,
        issuer_url=data.issuer_url,
        client_id=data.client_id,
        client_secret_encrypted=encrypted_secret,
        redirect_uri=redirect_uri,
        scopes=data.scopes,
        oauth2_proxy_port=data.oauth2_proxy_port,
        is_default=data.is_default,
        enabled=False,
        keycloak_admin_client_id=admin_client_id,
        keycloak_admin_client_secret_encrypted=admin_secret_encrypted,
        groups_sync_enabled=bool(admin_client_id and admin_secret_encrypted),
        keycloak_provision_client_id=provision_client_id,
        keycloak_provision_client_secret_encrypted=provision_secret_encrypted,
        provisioning_enabled=bool(
            provisioning_opt_in and provision_client_id and provision_secret_encrypted
        ),
    )
    db.add(realm)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        if not _is_oauth2_proxy_port_integrity_error(exc):
            raise
        try:
            new_port = get_next_available_port(db, settings)
            errors["oauth2_proxy_port"] = _port_collision_message(new_port)
            form_values["oauth2_proxy_port"] = new_port
            log_action(
                db,
                actor=user.email,
                action="realm.port_reallocated",
                target=data.slug,
                details={
                    "oauth2_proxy_port_requested": data.oauth2_proxy_port,
                    "oauth2_proxy_port": new_port,
                    "reason": "unique_constraint_collision",
                },
                ip_address=_client_ip(request),
            )
        except NoAvailablePortError as no_port:
            errors["oauth2_proxy_port"] = str(no_port)
        if _wants_json(request):
            return JSONResponse({"ok": False, "errors": errors}, status_code=400)
        return render(
            "admin/realm_form.html",
            **_ctx(request, settings, realm=None, form_values=form_values, errors=errors),
            status_code=400,
        )

    _apply_default_realm(db, realm, data.is_default)

    if enabled:
        test_result = await test_oidc_connection(
            data.issuer_url, data.client_id, data.client_secret
        )
        persist_test_result(realm, test_result)
        if test_result["status"] == "ok":
            realm.enabled = True

    db.commit()
    db.refresh(realm)
    log_action(
        db,
        actor=user.email,
        action="realm.created",
        target=realm.slug,
        details={"oauth2_proxy_port": realm.oauth2_proxy_port},
        ip_address=_client_ip(request),
    )

    if _wants_json(request):
        return JSONResponse({"ok": True, "id": realm.id, "slug": realm.slug})

    response = RedirectResponse(url="/admin/realms", status_code=302)
    flash_redirect(
        response,
        f"Realm '{realm.slug}' créé.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@router.get("/admin/realms/{realm_id}/edit")
def admin_realms_edit(
    realm_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    realm = db.query(RealmConfig).filter_by(id=realm_id).first()
    if not realm:
        raise HTTPException(status_code=404)
    return render(
        "admin/realm_form.html",
        **_ctx(
            request,
            settings,
            realm=realm,
            form_values=_realm_form_values(realm),
            errors={},
            encryption_error=_guard_encryption(settings),
        ),
    )


@router.post("/admin/realms/{realm_id}")
async def admin_realms_update(
    realm_id: int,
    request: Request,
    name: str = Form(""),
    issuer_url: str = Form(""),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    keycloak_admin_client_id: str = Form(""),
    keycloak_admin_client_secret: str = Form(""),
    keycloak_provision_client_id: str = Form(""),
    keycloak_provision_client_secret: str = Form(""),
    provisioning_enabled: str | None = Form(None),
    oauth2_proxy_port: int = Form(4180),
    scopes: str = Form("openid profile email"),
    is_default: str | None = Form(None),
    activate: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    realm = db.query(RealmConfig).filter_by(id=realm_id).first()
    if not realm:
        raise HTTPException(status_code=404)

    form_values = _realm_form_values(realm)
    form_values.update(
        {
            "name": name,
            "issuer_url": issuer_url,
            "client_id": client_id,
            "oauth2_proxy_port": oauth2_proxy_port,
            "scopes": scopes,
            "is_default": _form_bool(is_default),
            "keycloak_provision_client_id": keycloak_provision_client_id,
            "provisioning_enabled": _form_bool(provisioning_enabled),
        }
    )
    enabled_requested = _form_bool(activate)

    try:
        data = RealmConfigUpdate(
            name=name,
            issuer_url=issuer_url,
            client_id=client_id,
            client_secret=client_secret or None,
            keycloak_admin_client_id=keycloak_admin_client_id or None,
            keycloak_admin_client_secret=keycloak_admin_client_secret or None,
            keycloak_provision_client_id=keycloak_provision_client_id or None,
            keycloak_provision_client_secret=keycloak_provision_client_secret or None,
            provisioning_enabled=_form_bool(provisioning_enabled),
            oauth2_proxy_port=oauth2_proxy_port,
            scopes=scopes,
            is_default=_form_bool(is_default),
            enabled=enabled_requested,
        )
    except ValidationError as exc:
        errors = validation_errors_response(exc)["errors"]
        if _wants_json(request):
            return JSONResponse({"ok": False, "errors": errors}, status_code=400)
        return render(
            "admin/realm_form.html",
            **_ctx(request, settings, realm=realm, form_values=form_values, errors=errors),
            status_code=400,
        )

    errors: dict[str, str] = {}
    if port_err := _check_port_unique(db, data.oauth2_proxy_port, exclude_id=realm.id):
        errors["oauth2_proxy_port"] = port_err

    secret_for_test = _resolve_client_secret(data.client_secret, realm, settings)
    if enabled_requested and realm.last_test_status != "ok":
        if not secret_for_test:
            errors["client_secret"] = "Client secret requis pour activer"
        else:
            test_result = await test_oidc_connection(
                data.issuer_url, data.client_id, secret_for_test
            )
            if test_result["status"] != "ok":
                errors["_form"] = "Le test de connexion doit réussir avant l'activation"

    if errors:
        if _wants_json(request):
            return JSONResponse({"ok": False, "errors": errors}, status_code=400)
        return render(
            "admin/realm_form.html",
            **_ctx(request, settings, realm=realm, form_values=form_values, errors=errors),
            status_code=400,
        )

    # Only write port when it actually changes — avoids treating a no-op submit
    # as a reallocation (no purge/export/audit on identical port).
    port_changed = data.oauth2_proxy_port != realm.oauth2_proxy_port

    realm.name = data.name
    realm.issuer_url = data.issuer_url
    realm.client_id = data.client_id
    if port_changed:
        realm.oauth2_proxy_port = data.oauth2_proxy_port
    realm.scopes = data.scopes
    realm.redirect_uri = compute_redirect_uri(realm.slug, settings)
    if data.client_secret:
        encrypted_secret, enc_err = _safe_encrypt_secret(data.client_secret, settings)
        if enc_err:
            return render(
                "admin/realm_form.html",
                **_ctx(
                    request,
                    settings,
                    realm=realm,
                    form_values=form_values,
                    errors={"_form": enc_err},
                ),
                status_code=400,
            )
        realm.client_secret_encrypted = encrypted_secret

    admin_id = (data.keycloak_admin_client_id or "").strip() or None
    admin_secret_plain = (data.keycloak_admin_client_secret or "").strip() or None
    if admin_id or admin_secret_plain:
        if not admin_id:
            if _wants_json(request):
                return JSONResponse(
                    {"ok": False, "errors": {"keycloak_admin_client_id": "Client ID requis"}},
                    status_code=400,
                )
            return render(
                "admin/realm_form.html",
                **_ctx(
                    request,
                    settings,
                    realm=realm,
                    form_values=form_values,
                    errors={"keycloak_admin_client_id": "Client ID requis"},
                ),
                status_code=400,
            )
        if not admin_secret_plain and not realm.keycloak_admin_client_secret_encrypted:
            if _wants_json(request):
                return JSONResponse(
                    {"ok": False, "errors": {"keycloak_admin_client_secret": "Client secret requis"}},
                    status_code=400,
                )
            return render(
                "admin/realm_form.html",
                **_ctx(
                    request,
                    settings,
                    realm=realm,
                    form_values=form_values,
                    errors={"keycloak_admin_client_secret": "Client secret requis"},
                ),
                status_code=400,
            )

        realm.keycloak_admin_client_id = admin_id
        if admin_secret_plain:
            encrypted_admin, enc_err = _safe_encrypt_secret(admin_secret_plain, settings)
            if enc_err:
                return render(
                    "admin/realm_form.html",
                    **_ctx(
                        request,
                        settings,
                        realm=realm,
                        form_values=form_values,
                        errors={"_form": enc_err},
                    ),
                    status_code=400,
                )
            realm.keycloak_admin_client_secret_encrypted = encrypted_admin

    realm.groups_sync_enabled = bool(
        (realm.keycloak_admin_client_id or "").strip()
        and (realm.keycloak_admin_client_secret_encrypted or "").strip()
    )

    # --- Compte de service provisioning (écriture) ---
    provision_id = data.keycloak_provision_client_id
    provision_secret_plain = data.keycloak_provision_client_secret
    provision_errors: dict[str, str] = {}
    if provision_id or provision_secret_plain:
        if not provision_id:
            provision_errors["keycloak_provision_client_id"] = "Client ID requis"
        elif not provision_secret_plain and not realm.keycloak_provision_client_secret_encrypted:
            provision_errors["keycloak_provision_client_secret"] = "Client secret requis"
        else:
            realm.keycloak_provision_client_id = provision_id
            if provision_secret_plain:
                encrypted_provision, enc_err = _safe_encrypt_secret(
                    provision_secret_plain, settings
                )
                if enc_err:
                    provision_errors["_form"] = enc_err
                else:
                    realm.keycloak_provision_client_secret_encrypted = encrypted_provision
    # Opt-in EXPLICITE : jamais auto-dérivé de la présence des identifiants
    # (contrairement à groups_sync_enabled — écriture Keycloak = case consciente).
    want_provisioning = _form_bool(provisioning_enabled)
    if not provision_errors:
        if want_provisioning and not (
            (realm.keycloak_provision_client_id or "").strip()
            and (realm.keycloak_provision_client_secret_encrypted or "").strip()
        ):
            provision_errors["provisioning_enabled"] = (
                "Renseignez le compte de service provisioning avant d'activer le provisioning"
            )
        else:
            realm.provisioning_enabled = want_provisioning
    if provision_errors:
        if _wants_json(request):
            return JSONResponse({"ok": False, "errors": provision_errors}, status_code=400)
        return render(
            "admin/realm_form.html",
            **_ctx(
                request,
                settings,
                realm=realm,
                form_values=form_values,
                errors=provision_errors,
            ),
            status_code=400,
        )

    _apply_default_realm(db, realm, data.is_default)

    if enabled_requested:
        if realm.last_test_status != "ok" and secret_for_test:
            test_result = await test_oidc_connection(
                data.issuer_url, data.client_id, secret_for_test
            )
            persist_test_result(realm, test_result)
        activation_err = _guard_activation(realm, True)
        if activation_err:
            if _wants_json(request):
                return JSONResponse(
                    {"ok": False, "errors": {"_form": activation_err}}, status_code=400
                )
            return render(
                "admin/realm_form.html",
                **_ctx(
                    request,
                    settings,
                    realm=realm,
                    form_values=form_values,
                    errors={"_form": activation_err},
                ),
                status_code=400,
            )
        realm.enabled = True

    db.commit()
    log_action(
        db,
        actor=user.email,
        action="realm.updated",
        target=realm.slug,
        ip_address=_client_ip(request),
    )

    if _wants_json(request):
        return JSONResponse({"ok": True, "id": realm.id})

    response = RedirectResponse(url="/admin/realms", status_code=302)
    flash_redirect(
        response,
        f"Realm '{realm.slug}' mis à jour.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@router.post("/admin/realms/test")
async def admin_realms_test_draft(
    request: Request,
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    body = await request.json()
    try:
        data = RealmTestBody.model_validate(body)
    except ValidationError as exc:
        return JSONResponse(validation_errors_response(exc), status_code=400)

    if wait := throttle_retry_after(
        "oidc_realm", f"draft:{data.client_id}:{data.issuer_url}", min_interval_seconds=5
    ):
        return JSONResponse(
            {"ok": False, "errors": {"_form": f"Trop de tests — réessayez dans {wait:.0f}s"}},
            status_code=429,
        )

    result = await test_oidc_connection(data.issuer_url, data.client_id, data.client_secret)
    logger.info(
        "OIDC draft test issuer=%s status=%s",
        data.issuer_url,
        result["status"],
    )
    return JSONResponse({"ok": True, **result})


@router.post("/admin/realms/test-port")
async def admin_realms_test_port(
    request: Request,
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    body = await request.json()
    try:
        data = PortTestBody.model_validate(body)
    except ValidationError as exc:
        return JSONResponse(validation_errors_response(exc), status_code=400)

    if data.port < settings.oauth2_proxy_port_min or data.port > settings.oauth2_proxy_port_max:
        return JSONResponse(
            {
                "ok": False,
                "errors": {
                    "port": f"Le port doit être entre {settings.oauth2_proxy_port_min} et {settings.oauth2_proxy_port_max}"
                },
            },
            status_code=400,
        )

    result = test_port_available(data.port)
    return JSONResponse({"ok": True, **result})


@router.post("/admin/realms/{realm_id}/test")
async def admin_realms_test(
    realm_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    realm = db.query(RealmConfig).filter_by(id=realm_id).first()
    if not realm:
        raise HTTPException(status_code=404)

    if wait := throttle_retry_after("oidc_realm", realm_id, min_interval_seconds=5):
        return JSONResponse(
            {"ok": False, "errors": {"_form": f"Trop de tests — réessayez dans {wait:.0f}s"}},
            status_code=429,
        )

    body: dict[str, Any] = {}
    if request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()

    issuer_url = body.get("issuer_url", realm.issuer_url)
    client_id = body.get("client_id", realm.client_id)
    client_secret = _resolve_client_secret(body.get("client_secret"), realm, settings)
    if not client_secret:
        return JSONResponse(
            {"ok": False, "errors": {"client_secret": "Client secret requis"}},
            status_code=400,
        )

    result = await test_oidc_connection(issuer_url, client_id, client_secret)
    persist_test_result(realm, result)
    db.commit()

    log_action(
        db,
        actor=user.email,
        action="realm.test",
        target=realm.slug,
        details={"status": result["status"]},
        ip_address=_client_ip(request),
    )
    logger.info("OIDC test realm=%s status=%s", realm.slug, result["status"])
    return JSONResponse({"ok": True, **result})


def _error_response(request: Request, status_code: int, detail: str) -> JSONResponse | None:
    if _wants_json(request):
        return JSONResponse({"ok": False, "errors": {"_form": detail}}, status_code=status_code)
    return None


@router.post("/admin/realms/{realm_id}/enable")
def admin_realms_enable(
    realm_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    realm = db.query(RealmConfig).filter_by(id=realm_id).first()
    if not realm:
        raise HTTPException(status_code=404)
    if realm.last_test_status != "ok":
        if resp := _error_response(
            request,
            400,
            "Impossible d'activer un realm dont le test de connexion n'a pas réussi",
        ):
            return resp
        raise HTTPException(
            status_code=400,
            detail="Impossible d'activer un realm dont le test de connexion n'a pas réussi",
        )
    realm.enabled = True
    db.commit()
    log_action(
        db,
        actor=user.email,
        action="realm.enabled",
        target=realm.slug,
        ip_address=_client_ip(request),
    )
    if _wants_json(request):
        return JSONResponse({"ok": True})
    response = RedirectResponse(url="/admin/realms", status_code=302)
    flash_redirect(
        response,
        f"Realm '{realm.slug}' activé.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@router.post("/admin/realms/{realm_id}/disable")
def admin_realms_disable(
    realm_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    realm = db.query(RealmConfig).filter_by(id=realm_id).first()
    if not realm:
        raise HTTPException(status_code=404)
    realm.enabled = False
    db.commit()
    log_action(
        db,
        actor=user.email,
        action="realm.disabled",
        target=realm.slug,
        ip_address=_client_ip(request),
    )
    if _wants_json(request):
        return JSONResponse({"ok": True})
    response = RedirectResponse(url="/admin/realms", status_code=302)
    flash_redirect(
        response,
        f"Realm '{realm.slug}' désactivé.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@router.post("/admin/realms/{realm_id}/export")
def admin_realms_export(
    realm_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    realm = db.query(RealmConfig).filter_by(id=realm_id).first()
    if not realm:
        raise HTTPException(status_code=404)
    if realm.last_test_status != "ok":
        if resp := _error_response(
            request,
            409,
            "Export impossible : le test de connexion doit être en statut ok",
        ):
            return resp
        raise HTTPException(
            status_code=409,
            detail="Export impossible : le test de connexion doit être en statut ok",
        )

    paths = export_realm_files(realm, db, settings)
    db.commit()
    log_action(
        db,
        actor=user.email,
        action="realm.export",
        target=realm.slug,
        details=paths,
        ip_address=_client_ip(request),
    )
    message = (
        "Configuration exportée. Elle sera appliquée au prochain "
        "déploiement AWX (linux_sso_portal_docker.yml)."
    )
    if _wants_json(request):
        return JSONResponse({"ok": True, "message": message, "paths": paths})
    response = RedirectResponse(url="/admin/realms", status_code=302)
    flash_redirect(response, message, "success", settings.vault_portal_internal_token or "dev")
    return response


@router.delete("/admin/realms/{realm_id}")
def admin_realms_delete(
    realm_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    realm = db.query(RealmConfig).filter_by(id=realm_id).first()
    if not realm:
        raise HTTPException(status_code=404)
    if realm.is_default:
        if resp := _error_response(request, 400, "Impossible de supprimer le realm par défaut"):
            return resp
        raise HTTPException(status_code=400, detail="Impossible de supprimer le realm par défaut")
    if realm.enabled:
        if resp := _error_response(request, 400, "Impossible de supprimer un realm activé"):
            return resp
        raise HTTPException(status_code=400, detail="Impossible de supprimer un realm activé")

    slug = realm.slug
    released_port = realm.oauth2_proxy_port
    db.delete(realm)
    db.commit()
    # Full export purge: oauth2 configs + nginx rewrite + systemd purge marker for AWX.
    purge_paths = purge_realm_exports_after_delete(db, settings, deleted_slug=slug)
    log_action(
        db,
        actor=user.email,
        action="realm.deleted",
        target=slug,
        details={
            "oauth2_proxy_port": released_port,
            "purge": {
                "nginx_realms_conf": purge_paths.get("nginx_realms_conf"),
                "systemd_unit": purge_paths.get("systemd_unit"),
                "systemd_purge_list": purge_paths.get("systemd_purge_list"),
            },
        },
        ip_address=_client_ip(request),
    )
    if _wants_json(request):
        return JSONResponse({"ok": True})
    response = RedirectResponse(url="/admin/realms", status_code=302)
    flash_redirect(
        response,
        f"Realm '{slug}' supprimé.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response
