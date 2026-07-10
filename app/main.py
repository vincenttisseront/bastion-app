"""FastAPI entrypoint — SSO portal Phase 2."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.auth import router as auth_router
from app.breakglass import router as breakglass_router
from app.database import engine
from app.models import Base
from app.realm_service import router as realm_router
from app.services import router as apps_router

# Routers Phase 3+ (not activated)
# from app.proxy.proxy_service import router as proxy_router
# from app.subdomain.subdomain_auth import router as subdomain_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="bastion-app — SSO Portal",
    version="0.2.0",
    lifespan=lifespan,
)


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "phase": "2"}


app.include_router(auth_router)
app.include_router(breakglass_router)
app.include_router(apps_router)
app.include_router(realm_router)

# TODO Phase 3: proxy, subdomain, robotic
