"""FastAPI entrypoint — SSO portal Phase 5 + Bastion Pro UI."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.auth import router as auth_router
from app.admin.infrastructure import router as infrastructure_router
from app.admin.realms import router as admin_realms_router
from app.admin.rbac_access import router as admin_rbac_access_router
from app.admin.rbac_governance import router as admin_rbac_governance_router
from app.admin.rbac_groups import router as admin_rbac_groups_router
from app.admin.files import router as admin_files_router
from app.files.routes import router as files_browser_router
from app.admin.user_sessions import router as admin_user_sessions_router
from app.breakglass import admin_router as breakglass_admin_router
from app.breakglass import router as breakglass_router
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
from app.vault.routes import router as vault_router
from app.web.admin_dependencies import router as admin_dependencies_router
from app.web.admin_logs import router as admin_logs_router
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    import logging

    settings = get_settings()
    configure_logging(settings)
    logger = logging.getLogger("app.main")
    Base.metadata.create_all(bind=engine)
    from app.database import SessionLocal
    from app.vault.encryption_key_store import (
        EncryptionKeyStoreError,
        ensure_encryption_key,
    )
    from app.web.app_logos import ensure_logo_dir

    db = SessionLocal()
    try:
        version = ensure_encryption_key(db, settings)
        logger.info("vault encryption key ready version=%s", version)
    except EncryptionKeyStoreError:
        logger.exception("vault encryption key store failed — refusing to start")
        raise
    finally:
        db.close()

    ensure_logo_dir(settings)
    start_health_scheduler(settings)
    try:
        yield
    finally:
        stop_health_scheduler()


app = FastAPI(
    title="bastion-app — SSO Portal",
    version=APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(RequestIdMiddleware)
app.add_middleware(BreakglassCookieRotationMiddleware)

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


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "phase": "5"}


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
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
    if request.url.path.startswith("/api/"):
        raise exc
    settings = get_settings()
    ctx = base_template_context(request, settings, APP_VERSION, hide_chrome=True)
    return render("errors/500.html", **ctx, status_code=500)


app.include_router(pages_router)
app.include_router(pages_user_router)
app.include_router(pages_admin_router)
app.include_router(portal_router)
app.include_router(files_browser_router)
app.include_router(global_search_router)
app.include_router(health_router)
app.include_router(admin_realms_router)
app.include_router(infrastructure_router)
app.include_router(admin_rbac_groups_router)
app.include_router(admin_rbac_access_router)
app.include_router(admin_rbac_governance_router)
app.include_router(admin_files_router)
app.include_router(admin_user_sessions_router)
app.include_router(admin_logs_router)
app.include_router(admin_dependencies_router)
app.include_router(audit_router)
app.include_router(metrics_router)
app.include_router(sessions_router)
app.include_router(sessions_admin_router)
app.include_router(auth_router)
app.include_router(breakglass_router)
# Admin break-glass session APIs — guard attached here to avoid circular import
# with user_context (which imports breakglass for cookie validation).
app.include_router(breakglass_admin_router, dependencies=[Depends(require_admin)])
app.include_router(apps_read_router)
app.include_router(apps_router)
app.include_router(realm_router)
app.include_router(subdomain_router)
app.include_router(vault_router)
app.include_router(robotic_router)
app.include_router(session_cookie_hop_router)
