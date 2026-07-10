"""FastAPI entrypoint — SSO portal Phase 3 + Bastion Pro UI."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.auth import router as auth_router
from app.breakglass import router as breakglass_router
from app.database import engine
from app.models import Base
from app.realm_service import router as realm_router
from app.services import router as apps_router
from app.subdomain.subdomain_auth import router as subdomain_router
from app.web.audit_service import router as audit_router
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context
from app.web.metrics_service import router as metrics_router
from app.web.pages import router as pages_router
from app.web.sessions_service import router as sessions_router
from app.web.templates import render
from app.sso_settings import get_settings

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="bastion-app — SSO Portal",
    version=APP_VERSION,
    lifespan=lifespan,
)

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "phase": "3"}


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 401 and not request.url.path.startswith("/api/"):
        return RedirectResponse(url="/auth/login", status_code=302)
    if exc.status_code == 403 and not request.url.path.startswith("/api/"):
        settings = get_settings()
        ctx = base_template_context(request, settings, APP_VERSION, hide_chrome=True)
        return render("errors/403.html", **ctx, status_code=403)
    if exc.status_code == 404 and not request.url.path.startswith("/api/"):
        settings = get_settings()
        ctx = base_template_context(request, settings, APP_VERSION, hide_chrome=True)
        return render("errors/404.html", **ctx, status_code=404)
    raise exc


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    if request.url.path.startswith("/api/"):
        raise exc
    settings = get_settings()
    ctx = base_template_context(request, settings, APP_VERSION, hide_chrome=True)
    return render("errors/500.html", **ctx, status_code=500)


app.include_router(pages_router)
app.include_router(audit_router)
app.include_router(metrics_router)
app.include_router(sessions_router)
app.include_router(auth_router)
app.include_router(breakglass_router)
app.include_router(apps_router)
app.include_router(realm_router)
app.include_router(subdomain_router)

# TODO Phase 4: proxy, robotic
