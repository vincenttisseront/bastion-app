"""HTML page routes for Bastion Pro portal."""

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.access_modes import normalize_access_mode, validate_app_access_fields
from app.admin.export import export_app_catalogue_files
from app.audit import list_audit_entries, log_action
from app.health_probe import compute_health_score, compute_status_counts, probe_row_from_app
from app.auth_flow import get_default_idp_realm, oauth2_start_url, resolve_rd, setup_url
from app.breakglass import COOKIE_MAX_AGE, COOKIE_NAME, create_breakglass_token
from app.breakglass_store import (
    create_initial_breakglass_account,
    has_active_breakglass_account,
    verify_breakglass_password,
)
from app.database import get_db
from app.models import App, AppGroup, RBACGroup, RealmConfig
from app.rbac.grants_service import count_grants_by_application
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context, flash_redirect
from app.web.metrics_service import get_dashboard_metrics
from app.web.sessions_service import get_active_sessions, touch_portal_session
from app.web.templates import render
from app.web.user_context import get_user_context, is_portal_admin, require_admin, require_user

router = APIRouter(tags=["pages"])


def _ctx(request: Request, settings: Settings, **extra):
    return base_template_context(request, settings, APP_VERSION, **extra)


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "")


@router.get("/")
def root():
    return RedirectResponse(url="/apps", status_code=302)


@router.get("/dashboard")
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    touch_portal_session(db, user, _client_ip(request))
    metrics = get_dashboard_metrics(db)
    recent_audit, _ = list_audit_entries(db, limit=8)
    return render(
        "dashboard/index.html",
        **_ctx(request, settings, metrics=metrics, recent_audit=recent_audit),
    )


@router.get("/sessions")
def sessions_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_user),
    kind: str | None = Query(None),
):
    if is_portal_admin(user, db, settings):
        user.is_admin = True
    touch_portal_session(db, user, _client_ip(request))
    filter_kind = kind if kind in ("user", "app") else None
    sessions = get_active_sessions(db, viewer=user, kind=filter_kind)
    return render(
        "sessions/index.html",
        **_ctx(
            request,
            settings,
            sessions=sessions,
            session_kind=filter_kind or "all",
            session_counts={
                "all": len(get_active_sessions(db, viewer=user)),
                "user": len(get_active_sessions(db, viewer=user, kind="user")),
                "app": len(get_active_sessions(db, viewer=user, kind="app")),
            },
        ),
    )


@router.get("/catalogue")
def catalogue_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_user),
):
    apps = db.query(App).filter_by(enabled=True).order_by(App.label).all()
    if not user.is_admin and user.groups:
        allowed_ids = {
            link.app_id
            for link in db.query(AppGroup)
            .join(RBACGroup)
            .filter(RBACGroup.name.in_(user.groups))
            .all()
        }
        if allowed_ids:
            apps = [a for a in apps if a.id in allowed_ids]
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
    token = create_breakglass_token(username, settings.vault_portal_internal_token)
    response = RedirectResponse(url=rd, status_code=302)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        secure=False,
        samesite="lax",
    )
    log_action(
        db,
        actor=username,
        action="breakglass.login",
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
    if get_user_context(request, settings):
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

    if not verify_breakglass_password(db, username, password):
        log_action(
            db,
            actor=username,
            action="breakglass.login_failed",
            ip_address=_client_ip(request),
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


@router.get("/admin")
@router.get("/admin/dashboard")
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


@router.get("/admin/apps")
def admin_apps_list(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    apps = db.query(App).order_by(App.slug).all()
    return render("admin/apps/list.html", **_ctx(request, settings, apps=apps))


@router.get("/admin/apps/create")
def admin_apps_create(
    request: Request,
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
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
            },
            errors={},
        ),
    )


@router.post("/admin/apps/create")
def admin_apps_create_post(
    request: Request,
    slug: str = Form(...),
    label: str = Form(...),
    upstream_url: str = Form(...),
    access_mode: str = Form("sso_gate"),
    public_fqdn: str = Form(""),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    mode = normalize_access_mode(access_mode)
    fqdn = public_fqdn.strip() or None
    form_values = {
        "slug": slug,
        "label": label,
        "upstream_url": upstream_url,
        "access_mode": mode,
        "public_fqdn": public_fqdn,
    }
    errors = validate_app_access_fields(mode, upstream_url, fqdn)
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
    )
    db.add(app)
    db.commit()
    export_app_catalogue_files(db, settings)
    log_action(db, actor=user.email, action="app.created", target=slug)
    response = RedirectResponse(url="/admin/apps", status_code=302)
    flash_redirect(response, f"Application '{label}' créée.", "success", settings.vault_portal_internal_token or "dev")
    return response


@router.get("/admin/apps/{slug}/edit")
def admin_apps_edit(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    return render("admin/apps/edit.html", **_ctx(request, settings, app=app, errors={}))


@router.post("/admin/apps/{slug}/edit")
def admin_apps_edit_post(
    slug: str,
    request: Request,
    label: str = Form(...),
    upstream_url: str = Form(...),
    access_mode: str = Form("sso_gate"),
    public_fqdn: str = Form(""),
    enabled: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    mode = normalize_access_mode(access_mode)
    fqdn = public_fqdn.strip() or None
    errors = validate_app_access_fields(mode, upstream_url, fqdn)
    if errors:
        app.label = label
        app.upstream_url = upstream_url
        app.access_mode = mode
        app.public_fqdn = fqdn
        return render(
            "admin/apps/edit.html",
            **_ctx(request, settings, app=app, errors=errors),
        )
    app.label = label
    app.upstream_url = upstream_url
    app.access_mode = mode
    app.public_fqdn = fqdn
    app.enabled = enabled == "on"
    db.commit()
    export_app_catalogue_files(db, settings)
    log_action(db, actor=user.email, action="app.updated", target=slug)
    response = RedirectResponse(url="/admin/apps", status_code=302)
    flash_redirect(response, f"Application '{label}' mise à jour.", "success", settings.vault_portal_internal_token or "dev")
    return response


@router.get("/admin/rbac")
def admin_rbac(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    realms = db.query(RealmConfig).order_by(RealmConfig.slug).all()
    groups = db.query(RBACGroup).order_by(RBACGroup.name).all()
    apps = db.query(App).order_by(App.label).all()
    links = db.query(AppGroup).all()
    realms_by_id = {r.id: r for r in realms}
    return render(
        "admin/rbac.html",
        **_ctx(
            request,
            settings,
            realms=realms,
            realms_by_id=realms_by_id,
            groups=groups,
            apps=apps,
            links=links,
        ),
    )


@router.get("/admin/resources")
def admin_resources(
    request: Request,
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    return render("admin/resources.html", **_ctx(request, settings, resources=[]))


@router.get("/admin/security")
def admin_security(
    request: Request,
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    return render("admin/security.html", **_ctx(request, settings))


@router.get("/admin/health")
def admin_health(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
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
