"""HTML page routes for Bastion Pro portal."""

import logging

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.access_modes import normalize_access_mode, validate_app_access_fields
from app.auth import is_rfc1918
from app.bastion.bastion_fields import (
    normalize_auth_mode,
    normalize_credential_mode,
    normalize_identity_format,
    resolve_robotic_driver,
    validate_generic_form_fields,
    vault_enabled_for_app,
)
from app.robotic.robotic_session_cookies import normalize_injected_cookie_scope
from app.admin.export import export_app_catalogue_files
from app.audit import list_audit_entries, log_action
from app.health_probe import compute_health_score, compute_status_counts, probe_row_from_app
from app.auth_flow import get_default_idp_realm, oauth2_start_url, resolve_rd, setup_url
from app.breakglass import (
    COOKIE_NAME,
    issue_breakglass_token,
    resolve_breakglass_signing_secret,
    set_breakglass_cookie,
)
from app.breakglass_store import (
    create_initial_breakglass_account,
    has_active_breakglass_account,
    verify_breakglass_password,
)
from app.database import get_db
from app.models import App, RBACGroup, RealmConfig
from app.rbac.grants_service import count_grants_by_application
from app.robotic.robotic_session_cookies import shared_parent_domain
from app.sso_settings import Settings, get_settings
from app.web.app_logos import (
    LogoValidationError,
    clear_app_logo,
    logo_public_url,
    save_app_logo,
)
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context, flash_redirect
from app.web.metrics_service import get_dashboard_metrics
from app.request_client_ip import client_ip_from_request
from app.web.sessions_service import (
    build_session_groups,
    get_active_sessions,
    touch_portal_session,
)
from app.web.templates import render
from app.vault.app_credential_service import (
    EncryptionNotConfiguredError,
    VaultError,
    get_app_credential,
    set_app_credential,
)
from app.vault.credential_connection_test import (
    credential_test_legacy_response,
    test_app_credential_connection,
)
from app.vault.user_app_credential_service import (
    delete_user_credential,
    get_user_credential,
    has_user_override,
    set_user_credential,
)
from app.testing_framework.throttle import throttle_retry_after
from app.web.user_context import get_user_context, is_portal_admin, require_admin, require_user
from pydantic import BaseModel, Field

router = APIRouter(tags=["pages"])
# Authenticated (non-admin) pages — new routes inherit require_user.
authenticated_router = APIRouter(
    tags=["pages-user"],
    dependencies=[Depends(require_user)],
)
# Admin pages — new routes inherit require_admin.
admin_router = APIRouter(
    tags=["pages-admin"],
    dependencies=[Depends(require_admin)],
)

logger = logging.getLogger(__name__)

_DESC_MAX = 140


def _warn_if_fqdn_cookie_domain_incompatible(
    *,
    access_mode: str,
    public_fqdn: str | None,
    portal_domain: str,
    app_slug: str,
) -> None:
    if normalize_access_mode(access_mode) != "subdomain_proxy":
        return
    fqdn = (public_fqdn or "").strip()
    if not fqdn:
        return
    if shared_parent_domain(fqdn, portal_domain or "") is None:
        logger.warning(
            "App %s FQDN %r shares no parent domain with portal %r — "
            "cross-subdomain session cookies will never work for this combination",
            app_slug,
            fqdn,
            portal_domain,
        )


def _normalize_description(raw: str | None) -> str | None:
    text = (raw or "").strip()
    if not text:
        return None
    if len(text) > _DESC_MAX:
        text = text[:_DESC_MAX]
    return text


def _auth_form_values(
    auth_mode: str = "sso",
    login_form_url: str = "",
    login_username_field: str = "username",
    login_password_field: str = "password",
    login_http_method: str = "POST",
    login_extra_fields: str = "",
) -> dict:
    return {
        "auth_mode": normalize_auth_mode(auth_mode),
        "login_form_url": login_form_url,
        "login_username_field": login_username_field or "username",
        "login_password_field": login_password_field or "password",
        "login_http_method": (login_http_method or "POST").upper(),
        "login_extra_fields": login_extra_fields,
    }


def _apply_auth_config(
    app: App,
    *,
    auth_mode: str,
    login_form_url: str,
    login_username_field: str,
    login_password_field: str,
    login_http_method: str,
    login_extra_fields: str,
    credential_mode: str = "shared",
    identity_format: str = "email",
    injected_cookie_scope: str = "host_only",
) -> None:
    mode = normalize_auth_mode(auth_mode)
    app.auth_mode = mode
    app.robotic_driver = resolve_robotic_driver(mode, app.robotic_driver)
    app.login_form_url = (login_form_url or "").strip() or None
    app.login_username_field = (login_username_field or "username").strip() or "username"
    app.login_password_field = (login_password_field or "password").strip() or "password"
    app.login_http_method = (login_http_method or "POST").strip().upper()
    app.login_extra_fields = (login_extra_fields or "").strip() or None
    app.credential_mode = normalize_credential_mode(credential_mode)
    app.identity_format = normalize_identity_format(identity_format)
    app.injected_cookie_scope = normalize_injected_cookie_scope(injected_cookie_scope)


def _validate_auth_fields(
    access_mode: str,
    auth_mode: str,
    login_form_url: str,
    login_username_field: str,
    login_password_field: str,
    login_http_method: str,
    login_extra_fields: str,
) -> dict[str, str]:
    errors: dict[str, str] = {}
    mode = normalize_access_mode(access_mode)
    auth = normalize_auth_mode(auth_mode)
    if mode == "sso_gate" and auth != "sso":
        errors["auth_mode"] = "Le vault robotic n'est pas disponible en mode SSO Gate."
    if auth == "generic_form":
        errors.update(
            validate_generic_form_fields(
                login_form_url,
                login_username_field,
                login_password_field,
                login_http_method,
                login_extra_fields,
            )
        )
    return errors


def _ctx(request: Request, settings: Settings, **extra):
    return base_template_context(request, settings, APP_VERSION, **extra)


def _client_ip(request: Request) -> str:
    return client_ip_from_request(request)


@router.get("/")
def root():
    return RedirectResponse(url="/apps", status_code=302)


@admin_router.get("/dashboard")
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    touch_portal_session(db, user, _client_ip(request), request=request)
    metrics = get_dashboard_metrics(db)
    recent_audit, _ = list_audit_entries(db, limit=8)
    return render(
        "dashboard/index.html",
        **_ctx(request, settings, metrics=metrics, recent_audit=recent_audit),
    )


@authenticated_router.get("/sessions")
def sessions_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_user),
    kind: str | None = Query(None),
):
    if is_portal_admin(user, db, settings):
        user.is_admin = True
    touch_portal_session(db, user, _client_ip(request), request=request)
    filter_kind = kind if kind in ("user", "app") else None
    sessions = get_active_sessions(db, viewer=user, kind=filter_kind)
    return render(
        "sessions/index.html",
        **_ctx(
            request,
            settings,
            sessions=sessions,
            session_groups=build_session_groups(db, sessions),
            session_kind=filter_kind or "all",
            session_counts={
                "all": len(get_active_sessions(db, viewer=user)),
                "user": len(get_active_sessions(db, viewer=user, kind="user")),
                "app": len(get_active_sessions(db, viewer=user, kind="app")),
            },
        ),
    )


@authenticated_router.get("/catalogue")
def catalogue_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_user),
):
    from app.rbac.effective_access_service import get_effective_apps_for_user

    if is_portal_admin(user, db, settings):
        user.is_admin = True
        apps = db.query(App).filter_by(enabled=True).order_by(App.label).all()
    else:
        # Single source of truth: AccessGrant (legacy group↔app links backfilled as launch).
        entries = get_effective_apps_for_user(
            db,
            keycloak_user_id=user.keycloak_user_id,
            group_names=user.groups,
        )
        apps = [e.app for e in entries]
    grant_counts = count_grants_by_application(db) if user.is_admin else {}
    return render(
        "catalogue/index.html",
        **_ctx(request, settings, apps=apps, grant_counts=grant_counts),
    )


# --- Auth ---

_MIN_SETUP_PASSWORD_LEN = 12


def _breakglass_login_response(
    username: str,
    request: Request,
    settings: Settings,
    db: Session,
    rd: str,
) -> RedirectResponse:
    token, jti = issue_breakglass_token(
        db,
        username,
        resolve_breakglass_signing_secret(settings, db=db),
        request=request,
    )
    db.commit()
    response = RedirectResponse(url=rd, status_code=302)
    set_breakglass_cookie(response, token, settings)
    log_action(
        db,
        actor=username,
        action="breakglass.login",
        details={"jti": jti},
        ip_address=_client_ip(request),
    )
    flash_redirect(
        response,
        "Connexion break-glass réussie.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@router.get("/auth/login")
@router.get("/breakglass")
def login_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    rd = resolve_rd(request)
    if get_user_context(request, settings, db=db):
        return RedirectResponse(url=rd, status_code=302)

    realm = get_default_idp_realm(db)
    if not realm and not has_active_breakglass_account(db):
        return RedirectResponse(url=setup_url(rd), status_code=302)

    oauth2_url = oauth2_start_url(realm.slug, rd) if realm else None
    return render(
        "auth/login.html",
        **_ctx(request, settings, hide_chrome=True, rd=rd, oauth2_url=oauth2_url),
    )


@router.post("/auth/login")
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    rd: str = Form("/apps"),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    # Break-glass is never an end-user: default landing is admin dashboard.
    safe_rd = rd if rd.startswith("/") and not rd.startswith("//") else "/dashboard"
    if safe_rd == "/apps":
        safe_rd = "/dashboard"

    if not has_active_breakglass_account(db):
        raise HTTPException(status_code=403, detail="Initial setup required")

    # Defense in depth: Nginx LAN-restricts /breakglass, but this POST lives under
    # public /auth/ — never verify the break-glass password from a non-LAN IP.
    client_ip = _client_ip(request)
    if not is_rfc1918(client_ip, settings.rfc1918_cidrs):
        log_action(
            db,
            actor=username,
            action="breakglass.login_denied_non_lan",
            details={"reason": "client_ip_not_rfc1918"},
            ip_address=client_ip or None,
        )
        realm = get_default_idp_realm(db)
        oauth2_url = oauth2_start_url(realm.slug, safe_rd) if realm else None
        ctx = _ctx(
            request,
            settings,
            hide_chrome=True,
            login_error="Identifiants invalides.",
            rd=safe_rd,
            oauth2_url=oauth2_url,
        )
        return render("auth/login.html", **ctx)

    if not verify_breakglass_password(db, username, password):
        log_action(
            db,
            actor=username,
            action="breakglass.login_failed",
            ip_address=client_ip or None,
        )
        realm = get_default_idp_realm(db)
        oauth2_url = oauth2_start_url(realm.slug, safe_rd) if realm else None
        ctx = _ctx(
            request,
            settings,
            hide_chrome=True,
            login_error="Identifiants invalides.",
            rd=safe_rd,
            oauth2_url=oauth2_url,
        )
        return render("auth/login.html", **ctx)

    return _breakglass_login_response(username, request, settings, db, safe_rd)


@router.get("/auth/setup")
def setup_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    if get_default_idp_realm(db) or has_active_breakglass_account(db):
        raise HTTPException(status_code=403, detail="Setup is locked")
    rd = resolve_rd(request)
    return render(
        "auth/setup.html",
        **_ctx(request, settings, hide_chrome=True, rd=rd),
    )


@router.post("/auth/setup")
async def setup_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    rd: str = Form("/dashboard"),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    if get_default_idp_realm(db) or has_active_breakglass_account(db):
        raise HTTPException(status_code=403, detail="Setup is locked")

    # Setup always creates a break-glass admin — land on dashboard, not /apps.
    safe_rd = rd if rd.startswith("/") and not rd.startswith("//") else "/dashboard"
    if safe_rd == "/apps":
        safe_rd = "/dashboard"
    username = username.strip()
    errors: list[str] = []

    if not username:
        errors.append("Le nom d'utilisateur est requis.")
    if len(password) < _MIN_SETUP_PASSWORD_LEN:
        errors.append(f"Le mot de passe doit contenir au moins {_MIN_SETUP_PASSWORD_LEN} caractères.")
    if password != password_confirm:
        errors.append("Les mots de passe ne correspondent pas.")

    if errors:
        return render(
            "auth/setup.html",
            **_ctx(
                request,
                settings,
                hide_chrome=True,
                rd=safe_rd,
                setup_errors=errors,
                form_username=username,
            ),
        )

    try:
        create_initial_breakglass_account(db, username, password)
    except ValueError:
        raise HTTPException(status_code=403, detail="Setup is locked") from None

    log_action(
        db,
        actor=username,
        action="breakglass.setup",
        ip_address=_client_ip(request),
    )
    return _breakglass_login_response(username, request, settings, db, safe_rd)


@router.get("/auth/sso-start")
def sso_start(
    request: Request,
    settings: Settings = Depends(get_settings),
):
    realm = request.headers.get("X-Portal-Realm-Slug", settings.sso_portal_default_realm_slug)
    rd = request.headers.get("X-Portal-OAuth2-Rd", "/apps")
    redirect_url = f"/oauth2/{realm}/start?rd={rd}"
    return render(
        "auth/sso_redirect.html",
        **_ctx(request, settings, hide_chrome=True, redirect_url=redirect_url),
    )


@router.get("/logout")
def logout(request: Request, settings: Settings = Depends(get_settings)):
    response = RedirectResponse(url="/auth/login", status_code=302)
    response.delete_cookie(key=COOKIE_NAME)
    return response


@router.get("/health")
def health_page():
    return {"status": "ok"}


# --- Error pages ---


@router.get("/errors/403")
def error_403(request: Request, settings: Settings = Depends(get_settings)):
    return render(
        "errors/403.html",
        **_ctx(request, settings, hide_chrome=True),
        status_code=403,
    )


@router.get("/errors/404")
def error_404(request: Request, settings: Settings = Depends(get_settings)):
    return render(
        "errors/404.html",
        **_ctx(request, settings, hide_chrome=True),
        status_code=404,
    )


@router.get("/errors/500")
def error_500(request: Request, settings: Settings = Depends(get_settings)):
    return render(
        "errors/500.html",
        **_ctx(request, settings, hide_chrome=True),
        status_code=500,
    )


# --- Admin ---


@admin_router.get("/admin")
@admin_router.get("/admin/dashboard")
def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    app_count = db.query(App).count()
    realm_count = db.query(RealmConfig).count()
    metrics = get_dashboard_metrics(db)
    return render(
        "admin/dashboard.html",
        **_ctx(
            request,
            settings,
            app_count=app_count,
            realm_count=realm_count,
            metrics=metrics,
        ),
    )


@admin_router.get("/admin/apps")
def admin_apps_list(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    apps = db.query(App).order_by(App.slug).all()
    return render("admin/apps/list.html", **_ctx(request, settings, apps=apps))


@admin_router.get("/admin/apps/create")
def admin_apps_create(
    request: Request,
    settings: Settings = Depends(get_settings),
):
    return render(
        "admin/apps/create.html",
        **_ctx(
            request,
            settings,
            form_values={
                "slug": "",
                "label": "",
                "upstream_url": "",
                "access_mode": "sso_gate",
                "public_fqdn": "",
                "description": "",
                **_auth_form_values(),
            },
            errors={},
        ),
    )


@admin_router.post("/admin/apps/create")
def admin_apps_create_post(
    request: Request,
    slug: str = Form(...),
    label: str = Form(...),
    upstream_url: str = Form(...),
    access_mode: str = Form("sso_gate"),
    public_fqdn: str = Form(""),
    description: str = Form(""),
    auth_mode: str = Form("sso"),
    login_form_url: str = Form(""),
    login_username_field: str = Form("username"),
    login_password_field: str = Form("password"),
    login_http_method: str = Form("POST"),
    login_extra_fields: str = Form(""),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    mode = normalize_access_mode(access_mode)
    fqdn = public_fqdn.strip() or None
    desc = _normalize_description(description)
    auth_values = _auth_form_values(
        auth_mode,
        login_form_url,
        login_username_field,
        login_password_field,
        login_http_method,
        login_extra_fields,
    )
    form_values = {
        "slug": slug,
        "label": label,
        "upstream_url": upstream_url,
        "access_mode": mode,
        "public_fqdn": public_fqdn,
        "description": description,
        **auth_values,
    }
    errors = validate_app_access_fields(mode, upstream_url, fqdn)
    errors.update(
        _validate_auth_fields(
            mode,
            auth_mode,
            login_form_url,
            login_username_field,
            login_password_field,
            login_http_method,
            login_extra_fields,
        )
    )
    if len((description or "").strip()) > _DESC_MAX:
        errors["description"] = f"La description ne doit pas dépasser {_DESC_MAX} caractères."
    if db.query(App).filter_by(slug=slug).first():
        errors["slug"] = f"Le slug « {slug} » existe déjà."
    if errors:
        return render(
            "admin/apps/create.html",
            **_ctx(request, settings, form_values=form_values, errors=errors),
        )
    app = App(
        slug=slug,
        label=label,
        upstream_url=upstream_url,
        access_mode=mode,
        public_fqdn=fqdn,
        description=desc,
    )
    _apply_auth_config(
        app,
        auth_mode=auth_mode,
        login_form_url=login_form_url,
        login_username_field=login_username_field,
        login_password_field=login_password_field,
        login_http_method=login_http_method,
        login_extra_fields=login_extra_fields,
        credential_mode="shared",
    )
    db.add(app)
    db.commit()
    _warn_if_fqdn_cookie_domain_incompatible(
        access_mode=mode,
        public_fqdn=fqdn,
        portal_domain=settings.portal_domain,
        app_slug=slug,
    )
    export_app_catalogue_files(db, settings)
    log_action(db, actor=user.email, action="app.created", target=slug)
    response = RedirectResponse(url=f"/admin/apps/{slug}/edit", status_code=302)
    flash_redirect(
        response,
        f"Application '{label}' créée. Vous pouvez ajouter un logo.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.get("/admin/apps/{slug}/edit")
def admin_apps_edit(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    return render(
        "admin/apps/edit.html",
        **_ctx(
            request,
            settings,
            app=app,
            errors={},
            logo_url=logo_public_url(app),
            vault_enabled=vault_enabled_for_app(app.auth_mode, app.robotic_driver),
        ),
    )


@admin_router.post("/admin/apps/{slug}/edit")
def admin_apps_edit_post(
    slug: str,
    request: Request,
    label: str = Form(...),
    upstream_url: str = Form(...),
    access_mode: str = Form("sso_gate"),
    public_fqdn: str = Form(""),
    description: str = Form(""),
    enabled: str | None = Form(None),
    auth_mode: str = Form("sso"),
    login_form_url: str = Form(""),
    login_username_field: str = Form("username"),
    login_password_field: str = Form("password"),
    login_http_method: str = Form("POST"),
    login_extra_fields: str = Form(""),
    credential_mode: str = Form("shared"),
    identity_format: str = Form("email"),
    injected_cookie_scope: str = Form("host_only"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    mode = normalize_access_mode(access_mode)
    fqdn = public_fqdn.strip() or None
    desc = _normalize_description(description)
    errors = validate_app_access_fields(mode, upstream_url, fqdn)
    errors.update(
        _validate_auth_fields(
            mode,
            auth_mode,
            login_form_url,
            login_username_field,
            login_password_field,
            login_http_method,
            login_extra_fields,
        )
    )
    if len((description or "").strip()) > _DESC_MAX:
        errors["description"] = f"La description ne doit pas dépasser {_DESC_MAX} caractères."
    if errors:
        app.label = label
        app.upstream_url = upstream_url
        app.access_mode = mode
        app.public_fqdn = fqdn
        app.description = desc
        _apply_auth_config(
            app,
            auth_mode=auth_mode,
            login_form_url=login_form_url,
            login_username_field=login_username_field,
            login_password_field=login_password_field,
            login_http_method=login_http_method,
            login_extra_fields=login_extra_fields,
            credential_mode=credential_mode,
            identity_format=identity_format,
            injected_cookie_scope=injected_cookie_scope,
        )
        return render(
            "admin/apps/edit.html",
            **_ctx(
                request,
                settings,
                app=app,
                errors=errors,
                logo_url=logo_public_url(app),
                vault_enabled=vault_enabled_for_app(app.auth_mode, app.robotic_driver),
            ),
        )
    app.label = label
    app.upstream_url = upstream_url
    app.access_mode = mode
    app.public_fqdn = fqdn
    app.description = desc
    app.enabled = enabled == "on"
    _apply_auth_config(
        app,
        auth_mode=auth_mode,
        login_form_url=login_form_url,
        login_username_field=login_username_field,
        login_password_field=login_password_field,
        login_http_method=login_http_method,
        login_extra_fields=login_extra_fields,
        credential_mode=credential_mode,
        identity_format=identity_format,
        injected_cookie_scope=injected_cookie_scope,
    )
    db.commit()
    _warn_if_fqdn_cookie_domain_incompatible(
        access_mode=mode,
        public_fqdn=fqdn,
        portal_domain=settings.portal_domain,
        app_slug=slug,
    )
    export_app_catalogue_files(db, settings)
    log_action(db, actor=user.email, action="app.updated", target=slug)
    response = RedirectResponse(url="/admin/apps", status_code=302)
    flash_redirect(response, f"Application '{label}' mise à jour.", "success", settings.vault_portal_internal_token or "dev")
    return response


class _VaultCredentialBody(BaseModel):
    robotic_username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class _AnalyzeLoginFormBody(BaseModel):
    url: str = Field(min_length=1)


@admin_router.post("/admin/apps/analyze-login-form")
async def admin_analyze_login_form(
    body: _AnalyzeLoginFormBody,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    """Fetch a remote login page and detect form field names (no credentials sent)."""
    from app.bastion.login_form_analyzer import (
        AnalyzeLoginFormError,
        analyze_login_form_url,
    )

    try:
        result = await analyze_login_form_url(body.url.strip())
    except AnalyzeLoginFormError as exc:
        log_action(
            db,
            actor=user.email,
            action="app.login_form.analyzed",
            target=(body.url or "").strip()[:500],
            details={"error": exc.error, "forms_found": 0},
            ip_address=_client_ip(request),
        )
        return JSONResponse(
            {"error": exc.error, "message": exc.message},
            status_code=exc.status_code,
        )
    log_action(
        db,
        actor=user.email,
        action="app.login_form.analyzed",
        target=(body.url or "").strip()[:500],
        details={
            "forms_found": result["forms_found"],
            "fetched_url": result.get("fetched_url"),
            "actions": [f.get("action") for f in result.get("forms", [])],
        },
        ip_address=_client_ip(request),
    )
    return result


@admin_router.get("/admin/apps/{slug}/credential")
def admin_app_credential_read(
    slug: str,
    db: Session = Depends(get_db),
):
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    cred = get_app_credential(db, slug)
    if cred is None:
        raise HTTPException(status_code=404, detail=f"No credential for app '{slug}'")
    return {
        "robotic_username": cred.robotic_username,
        "is_active": cred.is_active,
        "created_at": cred.created_at,
        "rotated_at": cred.rotated_at,
    }


@admin_router.post("/admin/apps/{slug}/credential")
def admin_app_credential_save(
    slug: str,
    body: _VaultCredentialBody,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    if normalize_credential_mode(app.credential_mode) in (
        "individual_required",
        "identite_utilisateur",
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Compte partagé désactivé — cette application n'utilise pas le "
                "credential vault partagé dans ce mode."
            ),
        )
    try:
        cred = set_app_credential(
            db,
            slug,
            body.robotic_username.strip(),
            body.password,
            settings,
            actor=user.email,
            ip_address=_client_ip(request),
        )
    except EncryptionNotConfiguredError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except VaultError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "robotic_username": cred.robotic_username,
        "is_active": cred.is_active,
    }


@admin_router.post("/admin/apps/{slug}/credential/test")
async def admin_app_credential_test(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    if wait := throttle_retry_after("app_credential", slug, min_interval_seconds=5):
        return JSONResponse(
            {"ok": False, "error": f"Trop de tests — réessayez dans {wait:.0f}s"},
            status_code=429,
        )
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    result = await test_app_credential_connection(db, app, settings)
    log_action(
        db,
        actor=user.email,
        action="credential.test",
        target=f"app:{slug}",
        details={
            "resource_type": result.resource_type,
            "resource_id": slug,
            "status": result.overall_status.value,
            "checks": [{"name": c.name, "status": c.status.value} for c in result.checks],
        },
        ip_address=_client_ip(request),
    )
    body, status = credential_test_legacy_response(result)
    if status == 503:
        raise HTTPException(status_code=503, detail=body.get("error", "Encryption not configured"))
    if status != 200 or not body.get("ok"):
        return JSONResponse(body, status_code=status if status != 200 else 200)
    return body


@admin_router.get("/admin/apps/{slug}/users/{keycloak_user_id}/credential")
def admin_user_app_credential_read(
    slug: str,
    keycloak_user_id: str,
    db: Session = Depends(get_db),
):
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    override = has_user_override(db, slug, keycloak_user_id)
    user_cred = get_user_credential(db, slug, keycloak_user_id) if override else None
    shared = get_app_credential(db, slug)
    return {
        "app_slug": slug,
        "keycloak_user_id": keycloak_user_id,
        "has_override": override,
        "credential_source": "user_override" if override else "shared",
        "robotic_username": (
            user_cred.robotic_username if user_cred is not None else (
                shared.robotic_username if shared is not None else None
            )
        ),
        "shared_available": shared is not None and bool(shared.is_active),
    }


@admin_router.post("/admin/apps/{slug}/users/{keycloak_user_id}/credential")
def admin_user_app_credential_save(
    slug: str,
    keycloak_user_id: str,
    body: _VaultCredentialBody,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    try:
        cred = set_user_credential(
            db,
            slug,
            keycloak_user_id,
            body.robotic_username.strip(),
            body.password,
            settings,
            actor=user.email,
            ip_address=_client_ip(request),
        )
    except EncryptionNotConfiguredError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except VaultError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "has_override": True,
        "robotic_username": cred.robotic_username,
        "credential_source": "user_override",
    }


@admin_router.delete("/admin/apps/{slug}/users/{keycloak_user_id}/credential")
def admin_user_app_credential_delete(
    slug: str,
    keycloak_user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.rbac.governance_service import user_can_module_action
    from app.web.user_context import is_portal_admin

    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    if not user_can_module_action(
        db,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
        module_key="secret_vault",
        action="can_delete",
        is_portal_admin=is_portal_admin(user, db, settings),
    ):
        raise HTTPException(
            status_code=403,
            detail="Permission gouvernance secret_vault.can_delete refusée",
        )
    deleted = delete_user_credential(
        db,
        slug,
        keycloak_user_id,
        actor=user.email,
        ip_address=_client_ip(request),
    )
    return {"ok": True, "deleted": deleted, "has_override": False, "credential_source": "shared"}


@admin_router.post("/admin/apps/{slug}/users/{keycloak_user_id}/credential/test")
async def admin_user_app_credential_test(
    slug: str,
    keycloak_user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    throttle_id = f"{slug}:{keycloak_user_id}"
    if wait := throttle_retry_after("user_app_credential", throttle_id, min_interval_seconds=5):
        return JSONResponse(
            {"ok": False, "error": f"Trop de tests — réessayez dans {wait:.0f}s"},
            status_code=429,
        )
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    result = await test_app_credential_connection(
        db, app, settings, keycloak_user_id=keycloak_user_id
    )
    log_action(
        db,
        actor=user.email,
        action="credential.user.test",
        target=f"app:{slug}/user:{keycloak_user_id}",
        details={
            "resource_type": result.resource_type,
            "resource_id": slug,
            "keycloak_user_id": keycloak_user_id,
            "status": result.overall_status.value,
            "checks": [{"name": c.name, "status": c.status.value} for c in result.checks],
        },
        ip_address=_client_ip(request),
    )
    body, status = credential_test_legacy_response(result)
    if status == 503:
        raise HTTPException(status_code=503, detail=body.get("error", "Encryption not configured"))
    if status != 200 or not body.get("ok"):
        return JSONResponse(body, status_code=status if status != 200 else 200)
    return body


@admin_router.post("/admin/apps/{app_id}/logo")
async def admin_app_logo_upload(
    app_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    """Upload / replace app logo (admin only). Content-sniffed PNG/JPEG/WEBP, max 512 KB."""
    app = db.query(App).filter_by(id=app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application introuvable")
    raw = await file.read()
    try:
        save_app_logo(app, raw)
    except LogoValidationError as exc:
        return JSONResponse({"ok": False, "detail": str(exc)}, status_code=400)
    db.commit()
    log_action(db, actor=user.email, action="app.logo_updated", target=app.slug)
    return {"ok": True, "logo_url": logo_public_url(app)}


@admin_router.delete("/admin/apps/{app_id}/logo")
def admin_app_logo_delete(
    app_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    """Remove logo and fall back to tile_icon / generic icon on the portal."""
    app = db.query(App).filter_by(id=app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application introuvable")
    clear_app_logo(app)
    db.commit()
    log_action(db, actor=user.email, action="app.logo_removed", target=app.slug)
    return {"ok": True}


@admin_router.get("/admin/rbac")
async def admin_rbac(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    from app.rbac.governance_service import (
        excess_permission_alerts,
        role_distribution_summary,
    )
    from app.rbac.permission_seed import seed_governance_rbac
    from app.rbac.users_stats_service import avatar_color_for, avatar_initials
    from app.rbac.keycloak_admin import fetch_group_members
    from app.models import AccessGrant

    seed_governance_rbac(db)
    db.commit()

    realms = db.query(RealmConfig).order_by(RealmConfig.slug).all()
    groups = db.query(RBACGroup).order_by(RBACGroup.name).all()
    apps = db.query(App).order_by(App.label).all()
    realms_by_id = {r.id: r for r in realms}

    role_grants = {
        g.rbac_group_id: g
        for g in db.query(AccessGrant)
        .filter_by(subject_type="group", resource_type="rbac_role")
        .all()
        if g.rbac_group_id
    }

    group_cards: list[dict] = []
    for g in groups:
        realm = realms_by_id.get(g.realm_id) if g.realm_id else None
        previews: list[dict] = []
        more = 0
        if realm and g.keycloak_group_id:
            try:
                members = await fetch_group_members(realm, g.keycloak_group_id, settings)
            except Exception:
                members = []
            for m in members[:3]:
                display = (
                    m.get("email")
                    or m.get("username")
                    or " ".join(
                        p
                        for p in (m.get("firstName") or "", m.get("lastName") or "")
                        if p
                    )
                    or "?"
                )
                previews.append(
                    {
                        "display": display,
                        "initials": avatar_initials(display),
                        "avatar_color": avatar_color_for(display),
                    }
                )
            more = max(0, len(members) - len(previews))
        elif g.member_count and g.member_count > 0:
            # Fallback visual when Keycloak members unavailable
            label = g.name or "?"
            previews.append(
                {
                    "display": label,
                    "initials": avatar_initials(label),
                    "avatar_color": avatar_color_for(label),
                }
            )
            more = max(0, int(g.member_count) - 1)

        grant = role_grants.get(g.id)
        mode = "limited"
        role_id = None
        if grant and grant.access_level == "manage":
            mode = "total"
            role_id = grant.rbac_role_id
        elif grant:
            role_id = grant.rbac_role_id

        group_cards.append(
            {
                "id": g.id,
                "name": g.name,
                "path": g.path,
                "realm_slug": (realm.slug if realm else g.realm_slug),
                "group_tag": g.group_tag,
                "description": g.description,
                "member_count": int(g.member_count or len(previews) + more),
                "member_previews": previews,
                "member_more": more,
                "role_mode": mode,
                "rbac_role_id": role_id,
            }
        )

    return render(
        "admin/rbac.html",
        **_ctx(
            request,
            settings,
            realms=realms,
            realms_by_id=realms_by_id,
            groups=groups,
            apps=apps,
            group_cards=group_cards,
            role_distribution=role_distribution_summary(db),
            excess_alerts=excess_permission_alerts(db),
            active_tab="groups",
        ),
    )


@admin_router.get("/admin/security")
def admin_security(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    from app.breakglass import resolve_breakglass_signing_secret_with_source
    from app.breakglass_secret_service import build_breakglass_secret_status
    from app.db_cipher import get_db_encryption_status
    from app.portal_settings_service import get_subdomain_sso_enabled
    from app.vault.encryption_key_store import get_vault_key_status

    subdomain_apps = (
        db.query(App)
        .filter(App.access_mode == "subdomain_proxy", App.enabled.is_(True))
        .order_by(App.label)
        .all()
    )
    vault_status = get_vault_key_status(db, settings)
    db_encryption = get_db_encryption_status(settings)
    bg_secret, bg_source = resolve_breakglass_signing_secret_with_source(
        settings, db=db
    )
    breakglass_secret = build_breakglass_secret_status(
        settings,
        db,
        effective_secret=bg_secret,
        effective_source=bg_source,
    )
    return render(
        "admin/security.html",
        **_ctx(
            request,
            settings,
            subdomain_sso_enabled=get_subdomain_sso_enabled(db, settings),
            subdomain_apps=subdomain_apps,
            vault_key=vault_status,
            db_encryption=db_encryption,
            breakglass_secret=breakglass_secret.to_public_dict(),
        ),
    )


@admin_router.post("/admin/security/breakglass-jwt-secret/generate")
def admin_security_breakglass_jwt_secret_generate(
    request: Request,
    confirm: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.breakglass_secret_service import (
        env_breakglass_secret_defined,
        generate_or_rotate_ui_breakglass_secret,
    )

    token = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/admin/security#breakglass-jwt", status_code=302)
    if env_breakglass_secret_defined(settings):
        flash_redirect(
            response,
            "Secret déjà défini via BREAKGLASS_JWT_SECRET (AWX) — génération UI désactivée.",
            "error",
            token,
        )
        return response
    if confirm != "on":
        flash_redirect(
            response,
            "Génération annulée : confirmation requise.",
            "error",
            token,
        )
        return response
    actor = user.email or user.username or "admin"
    ip = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    try:
        generate_or_rotate_ui_breakglass_secret(
            db, settings, actor=actor, ip_address=ip
        )
    except PermissionError as exc:
        flash_redirect(response, str(exc), "error", token)
        return response
    except ValueError as exc:
        flash_redirect(response, str(exc), "error", token)
        return response

    from app.breakglass_secret_service import get_ui_breakglass_previous_secret

    if get_ui_breakglass_previous_secret(db, settings):
        msg = (
            "Secret break-glass régénéré (rotation). Les cookies déjà émis restent "
            "valides pendant la transition."
        )
    else:
        msg = "Secret break-glass dédié généré et actif."
    flash_redirect(response, msg, "success", token)
    return response


@admin_router.get("/admin/security/vault-key")
def admin_security_vault_key_redirect():
    return RedirectResponse(url="/admin/security#vault", status_code=302)


@admin_router.post("/admin/security/vault-key/rotate")
def admin_security_vault_key_rotate(
    request: Request,
    confirm: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.vault.key_rotation_service import KeyRotationError, rotate_application_key

    token = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/admin/security#vault", status_code=302)
    if confirm != "on":
        flash_redirect(
            response,
            "Rotation annulée : confirmation requise.",
            "error",
            token,
        )
        return response
    actor = user.email or user.username or "admin"
    ip = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    try:
        report = rotate_application_key(
            db, settings, actor=actor, ip_address=ip
        )
        flash_redirect(
            response,
            f"Clé Fernet renouvelée (version active). {report.total} secret(s) ré-chiffré(s).",
            "success",
            token,
        )
    except KeyRotationError:
        flash_redirect(
            response,
            "Échec de la rotation — base inchangée (rollback). Voir les logs admin.",
            "error",
            token,
        )
    return response


@admin_router.post("/admin/security/vault-key/cadence")
def admin_security_vault_key_cadence(
    request: Request,
    rotation_days: int = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.portal_settings_service import set_vault_key_rotation_days

    token = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/admin/security#vault", status_code=302)
    days = max(1, min(3650, int(rotation_days)))
    set_vault_key_rotation_days(
        db,
        settings,
        days,
        actor=user.email or user.username or "admin",
        ip_address=request.headers.get("X-Real-IP")
        or (request.client.host if request.client else None),
    )
    flash_redirect(
        response,
        f"Cadence de rotation enregistrée : {days} jours (aucune rotation automatique).",
        "success",
        token,
    )
    return response


@admin_router.post("/admin/security/vault-key/export")
def admin_security_vault_key_export(
    passphrase: str = Form(...),
    passphrase_confirm: str = Form(...),
    settings: Settings = Depends(get_settings),
):
    from fastapi.responses import Response

    from app.vault.encryption_key_store import (
        EncryptionKeyStoreError,
        export_active_key_backup,
        get_active_version,
    )

    if passphrase != passphrase_confirm:
        response = RedirectResponse(url="/admin/security#vault", status_code=302)
        flash_redirect(
            response,
            "Export annulé : les passphrases ne correspondent pas.",
            "error",
            settings.vault_portal_internal_token or "dev",
        )
        return response
    try:
        payload = export_active_key_backup(settings, passphrase)
    except EncryptionKeyStoreError as exc:
        response = RedirectResponse(url="/admin/security#vault", status_code=302)
        flash_redirect(
            response,
            str(exc),
            "error",
            settings.vault_portal_internal_token or "dev",
        )
        return response
    version = get_active_version() or 0
    return Response(
        content=payload,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": (
                f'attachment; filename="bastion-fernet-v{version}.backup"'
            ),
        },
    )


@admin_router.post("/admin/security/subdomain-sso")
def admin_security_subdomain_sso(
    request: Request,
    enabled: str | None = Form(None),
    infra_ack: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.portal_settings_service import set_subdomain_sso_enabled

    want_enabled = enabled == "on"
    if want_enabled and infra_ack != "on":
        response = RedirectResponse(url="/admin/security#subdomain-sso", status_code=302)
        flash_redirect(
            response,
            "Activation refusée : confirmez d'abord que l'infrastructure sous-domaine est prête.",
            "error",
            settings.vault_portal_internal_token or "dev",
        )
        return response

    set_subdomain_sso_enabled(
        db,
        settings,
        want_enabled,
        actor=user.email or user.username or "admin",
        ip_address=request.headers.get("X-Real-IP")
        or (request.client.host if request.client else None),
    )
    response = RedirectResponse(url="/admin/security#subdomain-sso", status_code=302)
    flash_redirect(
        response,
        "Routage par sous-domaine "
        + ("activé." if want_enabled else "désactivé."),
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.get("/admin/health")
def admin_health(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    apps = db.query(App).filter_by(enabled=True).order_by(App.label).all()
    probes = [probe_row_from_app(app) for app in apps]
    status_counts = compute_status_counts(probes)
    total = len(probes)
    health_score = compute_health_score(status_counts, total)
    return render(
        "admin/health.html",
        **_ctx(
            request,
            settings,
            probes=probes,
            status_counts=status_counts,
            health_score=health_score,
        ),
    )
