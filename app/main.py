"""FastAPI entrypoint — SSO portal Phase 5 + Bastion Pro UI."""

from contextlib import asynccontextmanager
from pathlib import Path
import logging

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.auth import router as auth_router
from app.admin.infrastructure import router as infrastructure_router
from app.bastion.unknown_host_routes import router as unknown_host_router
from app.admin.realms import router as admin_realms_router
from app.admin.acme import router as admin_acme_router
from app.admin.rbac_access import router as admin_rbac_access_router
from app.admin.rbac_accounts import router as admin_rbac_accounts_router
from app.admin.rbac_governance import router as admin_rbac_governance_router
from app.admin.rbac_groups import router as admin_rbac_groups_router
from app.admin.files import router as admin_files_router
from app.files.routes import router as files_browser_router
from app.admin.user_sessions import router as admin_user_sessions_router
from app.breakglass import admin_router as breakglass_admin_router
from app.breakglass import router as breakglass_router
from app.oidc_bff import router as oidc_bff_router
from app.database import engine
from app.health_scheduler import start_health_scheduler, stop_health_scheduler
from app.logging_config import configure_logging
from app.breakglass_cookie_middleware import BreakglassCookieRotationMiddleware
from app.logging_middleware import RequestIdMiddleware
from app.models import Base
from app.realm_service import router as realm_router
from app.robotic.client_open_action import router as robotic_router
from app.robotic.session_cookie_hop import router as session_cookie_hop_router
from app.services import authenticated_router as apps_read_router
from app.services import router as apps_router
from app.subdomain.subdomain_auth import router as subdomain_router
from app.subdomain.activesync_auth import router as activesync_router
from app.vault.routes import router as vault_router
from app.web.admin_branding import router as admin_branding_router
from app.web.admin_configuration import router as admin_configuration_router
from app.web.admin_dependencies import router as admin_dependencies_router
from app.web.admin_infrastructure import router as admin_infrastructure_router
from app.web.admin_logs import router as admin_logs_router
from app.web.notifications_routes import router as admin_notifications_router
from app.web.audit_service import router as audit_router
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context
from app.web.global_search import router as global_search_router
from app.web.health_service import router as health_router
from app.web.metrics_service import router as metrics_router
from app.web.pages import admin_router as pages_admin_router
from app.web.pages import authenticated_router as pages_user_router
from app.web.pages import router as pages_router
from app.web.portal import router as portal_router
from app.web.sessions_service import admin_router as sessions_admin_router
from app.web.sessions_service import router as sessions_router
from app.web.templates import render
from app.web.user_context import require_admin
from app.sso_settings import get_settings

STATIC_DIR = Path(__file__).resolve().parent / "static"
logger = logging.getLogger("app.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings)

    Base.metadata.create_all(bind=engine)
    from app.database import SessionLocal
    from app.db.hot_store import sync_hot_engine_from_config
    from app.runtime_secrets_service import (
        ensure_portal_runtime_secrets,
        resolve_session_hop_secret,
    )
    from app.vault.encryption_key_store import (
        EncryptionKeyStoreError,
        ensure_encryption_key,
    )
    from app.branding import ensure_branding_dir
    from app.web.app_logos import ensure_logo_dir

    db = SessionLocal()
    try:
        version = ensure_encryption_key(db, settings)
        logger.info("vault encryption key ready version=%s", version)
        # HMAC hop / break-glass: SQLite is source of truth (migrate seeds them).
        # Env SESSION_HOP_SECRET / BREAKGLASS_JWT_SECRET remain optional overrides.
        # Skip ensure under pytest (PORTAL_ENVIRONMENT=test) — TestClient uses a
        # separate DB engine than SessionLocal; hop secret comes from conftest env.
        if not settings.is_test:
            ensure_portal_runtime_secrets(db, settings, actor="lifespan")
            hop = resolve_session_hop_secret(settings, db=db)
            if not hop:
                raise RuntimeError(
                    "SESSION_HOP_SECRET missing after ensure "
                    "(set env override or check portal_settings / migrate)"
                )
            from app.security.banning.engine import ensure_security_defaults

            ensure_security_defaults(db)
        try:
            sync_hot_engine_from_config(db, settings)
        except Exception:
            logger.exception("hot store: failed to sync engine at startup (non-fatal)")
        if (
            not settings.is_production
            and not settings.is_test
            and not (settings.breakglass_jwt_secret or "").strip()
        ):
            logger.warning(
                "BREAKGLASS_JWT_SECRET unset — using SQLite/UI secret or legacy "
                "VAULT_PORTAL_INTERNAL_TOKEN fallback; prefer a dedicated secret"
            )
    except EncryptionKeyStoreError:
        logger.exception("vault encryption key store failed — refusing to start")
        raise
    finally:
        db.close()

    ensure_logo_dir(settings)
    ensure_branding_dir(settings)
    start_health_scheduler(settings)
    from app.siem.worker import start_siem_scheduler, stop_siem_scheduler

    start_siem_scheduler(settings)
    try:
        yield
    finally:
        stop_siem_scheduler()
        stop_health_scheduler()


app = FastAPI(
    title="bastion-app — SSO Portal",
    version=APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(RequestIdMiddleware)
app.add_middleware(BreakglassCookieRotationMiddleware)

from app.security.banning.middleware import SecurityBanMiddleware  # noqa: E402

app.add_middleware(SecurityBanMiddleware)

# Neutral public aliases — registered before the /static mount.
_PORTAL_STATIC_ALIASES = {
    "/static/portal.css": ("css/bastion.css", "text/css"),
    "/static/portal-theme.js": ("js/bastion-theme.js", "application/javascript"),
    "/static/portal-busy.js": ("js/bastion-busy.js", "application/javascript"),
    "/static/portal-modal.js": ("js/bastion-modal.js", "application/javascript"),
    "/static/portal-login.js": ("js/bastion-login.js", "application/javascript"),
}


def _register_portal_static_aliases(application: FastAPI) -> None:
    root = STATIC_DIR.resolve()

    def _make_handler(rel: str, media: str):
        async def _serve():
            path = (STATIC_DIR / rel).resolve()
            if not str(path).startswith(str(root)) or not path.is_file():
                raise HTTPException(status_code=404, detail="Not found")
            return FileResponse(
                path,
                media_type=media,
                headers={"Cache-Control": "public, max-age=604800"},
            )

        return _serve

    for url_path, (rel, media) in _PORTAL_STATIC_ALIASES.items():
        application.add_api_route(
            url_path,
            _make_handler(rel, media),
            methods=["GET"],
            include_in_schema=False,
        )


_register_portal_static_aliases(app)

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/media/app-logos/{filename}")
async def serve_app_logo(filename: str):
    """Serve catalogue logos from PORTAL_DATA_DIR (not package static/)."""
    from app.web.app_logos import (
        logo_filename,
        media_type_for_filename,
        resolve_logo_file,
    )

    safe = logo_filename(filename)
    if safe is None or safe != filename:
        raise HTTPException(status_code=404, detail="Not found")
    path = resolve_logo_file(safe)
    if path is None:
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(
        path,
        media_type=media_type_for_filename(safe),
        headers={"Cache-Control": "public, max-age=604800"},
    )


@app.get("/media/branding/{filename}")
async def serve_branding_asset(filename: str):
    """Serve branding logo/favicon from PORTAL_DATA_DIR."""
    from app.branding import media_type_for_branding_filename, resolve_branding_file

    path = resolve_branding_file(filename)
    if path is None:
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(
        path,
        media_type=media_type_for_branding_filename(filename),
        headers={"Cache-Control": "public, max-age=604800"},
    )


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "phase": "5"}


def _admin_logs_api_path(path: str) -> bool:
    """JSON/SSE under /admin/logs — never HTML-redirect on 403."""
    return path == "/admin/logs/stream" or path.startswith("/admin/logs/containers/")


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    path = request.url.path
    # Native OIDC BFF + REST APIs: return JSON (do not HTML-redirect /auth/login → itself).
    if (
        path.startswith("/api/")
        or path in ("/auth/login", "/auth/logout")
        or _admin_logs_api_path(path)
    ):
        return JSONResponse(
            {"detail": exc.detail},
            status_code=exc.status_code,
            headers=dict(exc.headers) if exc.headers else None,
        )
    wants_json = "application/json" in (request.headers.get("accept") or "").lower()
    if exc.status_code == 401:
        if wants_json:
            return JSONResponse({"detail": exc.detail}, status_code=401)
        return RedirectResponse(url="/auth/login", status_code=302)
    if exc.status_code == 403:
        if wants_json:
            return JSONResponse({"detail": exc.detail}, status_code=403)
        # Authenticated end-users hitting /dashboard or /admin → home launcher
        from app.web.user_context import get_user_context

        settings = get_settings()
        if get_user_context(request, settings) is not None:
            return RedirectResponse(url="/apps", status_code=302)
        ctx = base_template_context(request, settings, APP_VERSION, hide_chrome=True)
        return render("errors/403.html", **ctx, status_code=403)
    if exc.status_code == 404:
        settings = get_settings()
        ctx = base_template_context(request, settings, APP_VERSION, hide_chrome=True)
        return render("errors/404.html", **ctx, status_code=404)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception("unhandled error path=%s", request.url.path)
    if request.url.path.startswith("/api/"):
        raise exc
    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept:
        return JSONResponse(
            {
                "ok": False,
                "errors": {"_form": "Erreur interne — l’incident a été journalisé."},
            },
            status_code=500,
        )
    settings = get_settings()
    ctx = base_template_context(request, settings, APP_VERSION, hide_chrome=True)
    return render("errors/500.html", **ctx, status_code=500)


app.include_router(pages_router)
app.include_router(pages_user_router)
app.include_router(pages_admin_router)
app.include_router(unknown_host_router)
app.include_router(portal_router)
app.include_router(files_browser_router)
app.include_router(global_search_router)
app.include_router(health_router)
app.include_router(admin_realms_router)
app.include_router(admin_acme_router)
app.include_router(infrastructure_router)
app.include_router(admin_rbac_groups_router)
# Before rbac_access: /admin/rbac/users/new must win over /admin/rbac/users/{keycloak_user_id}.
app.include_router(admin_rbac_accounts_router)
app.include_router(admin_rbac_access_router)
app.include_router(admin_rbac_governance_router)
app.include_router(admin_files_router)
app.include_router(admin_user_sessions_router)
app.include_router(admin_logs_router)
app.include_router(admin_notifications_router)
app.include_router(admin_dependencies_router)
app.include_router(admin_branding_router)
app.include_router(admin_configuration_router)
app.include_router(admin_infrastructure_router)
app.include_router(audit_router)
app.include_router(metrics_router)
app.include_router(sessions_router)
app.include_router(sessions_admin_router)
app.include_router(auth_router)
app.include_router(oidc_bff_router)
app.include_router(breakglass_router)
# Admin break-glass session APIs — guard attached here to avoid circular import
# with user_context (which imports breakglass for cookie validation).
app.include_router(breakglass_admin_router, dependencies=[Depends(require_admin)])
app.include_router(apps_read_router)
app.include_router(apps_router)
app.include_router(realm_router)
app.include_router(subdomain_router)
app.include_router(activesync_router)
app.include_router(vault_router)
app.include_router(robotic_router)
app.include_router(session_cookie_hop_router)
