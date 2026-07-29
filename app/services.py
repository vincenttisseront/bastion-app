"""Application catalogue CRUD (mutations via internal token)."""

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.access_modes import is_user_catalogue_mode, normalize_access_mode, validate_app_access_fields
from app.audit import log_action
from app.database import get_db
from app.models import App
from app.rbac.effective_access_service import get_effective_apps_for_user
from app.security import require_internal_token
from app.sso_settings import Settings, get_settings
from app.web.user_context import UserContext, is_portal_admin, require_user_enriched

# Authenticated catalogue reads (portal alignment). Mutations use ``router`` below.
authenticated_router = APIRouter(
    prefix="/api/apps",
    tags=["apps"],
    dependencies=[Depends(require_user_enriched)],
)
# Machine-to-machine catalogue mutations.
router = APIRouter(
    prefix="/api/apps",
    tags=["apps"],
    dependencies=[Depends(require_internal_token)],
)


class AppCreate(BaseModel):
    slug: str
    label: str
    upstream_url: str
    realm_slug: str | None = None
    access_mode: Literal[
        "sso_gate", "subdomain_proxy", "legacy_path_proxy", "public_proxy"
    ] = "sso_gate"
    public_fqdn: str | None = None
    auth_mode: str = "sso"
    robotic_driver: str | None = None
    login_form_url: str | None = None
    login_username_field: str = "username"
    login_password_field: str = "password"
    login_extra_fields: str | None = None
    login_http_method: str = "POST"
    credential_mode: Literal["shared", "individual_required", "identite_utilisateur"] = "shared"
    identity_format: Literal["email", "username"] = "email"
    healthcheck_url: str | None = None
    enabled: bool = True
    allow_activesync: bool = False
    upstream_tls_verify: bool = False
    tile_icon: str | None = None
    description: str | None = None
    logo_path: str | None = None


class AppUpdate(BaseModel):
    label: str | None = None
    upstream_url: str | None = None
    realm_slug: str | None = None
    access_mode: (
        Literal["sso_gate", "subdomain_proxy", "legacy_path_proxy", "public_proxy"] | None
    ) = None
    public_fqdn: str | None = None
    auth_mode: str | None = None
    robotic_driver: str | None = None
    login_form_url: str | None = None
    login_username_field: str | None = None
    login_password_field: str | None = None
    login_extra_fields: str | None = None
    login_http_method: str | None = None
    credential_mode: Literal["shared", "individual_required", "identite_utilisateur"] | None = None
    identity_format: Literal["email", "username"] | None = None
    healthcheck_url: str | None = None
    enabled: bool | None = None
    allow_activesync: bool | None = None
    upstream_tls_verify: bool | None = None
    tile_icon: str | None = None
    description: str | None = None
    logo_path: str | None = None


class AppOut(BaseModel):
    slug: str
    label: str
    upstream_url: str
    realm_slug: str | None
    access_mode: str
    public_fqdn: str | None
    auth_mode: str
    robotic_driver: str | None
    login_form_url: str | None = None
    login_username_field: str = "username"
    login_password_field: str = "password"
    login_extra_fields: str | None = None
    login_http_method: str = "POST"
    credential_mode: str = "shared"
    identity_format: str = "email"
    healthcheck_url: str | None
    enabled: bool
    allow_activesync: bool = False
    upstream_tls_verify: bool = False
    tile_icon: str | None
    description: str | None = None
    logo_path: str | None = None

    model_config = {"from_attributes": True}


def _app_to_out(app: App) -> AppOut:
    return AppOut.model_validate(app)


def _get_app_or_404(db: Session, slug: str) -> App:
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404, detail=f"App '{slug}' not found")
    return app


def get_app_by_slug_or_404(db: Session, slug: str) -> App:
    """Public lookup used by vault / robotic modules (avoids ad-hoc queries)."""
    return _get_app_or_404(db, slug)


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "")


def _apps_visible_to_user(
    db: Session,
    user: UserContext,
    settings: Settings,
) -> list[App]:
    """
    Catalogue API visibility (F-03).

    Portal admins / break-glass (via is_portal_admin) see all enabled apps —
    same rule as ``catalogue_page``. End users see AccessGrant-effective apps only.
    Full admin CRUD remains on ``/admin/apps`` (HTML) and token-mutated ``router``.
    """
    if is_portal_admin(user, db, settings):
        apps = db.query(App).filter_by(enabled=True).order_by(App.label).all()
        return [a for a in apps if is_user_catalogue_mode(a.access_mode)]
    entries = get_effective_apps_for_user(
        db,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
    )
    return [e.app for e in entries]


@authenticated_router.get("", response_model=list[AppOut])
def list_apps(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    return [_app_to_out(app) for app in _apps_visible_to_user(db, user, settings)]


@authenticated_router.get("/{slug}", response_model=AppOut)
def get_app(
    slug: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    app = _get_app_or_404(db, slug)
    if not app.enabled:
        raise HTTPException(status_code=404, detail=f"App '{slug}' not found")
    visible = {a.slug for a in _apps_visible_to_user(db, user, settings)}
    if app.slug not in visible:
        raise HTTPException(status_code=404, detail=f"App '{slug}' not found")
    return _app_to_out(app)


@router.post("", response_model=AppOut, status_code=201)
def create_app(
    body: AppCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    existing = db.query(App).filter_by(slug=body.slug).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"App '{body.slug}' already exists")

    mode = normalize_access_mode(body.access_mode)
    field_errors = validate_app_access_fields(mode, body.upstream_url, body.public_fqdn)
    if field_errors:
        raise HTTPException(status_code=422, detail=field_errors)

    payload = body.model_dump()
    payload["access_mode"] = mode
    if mode != "subdomain_proxy":
        payload["allow_activesync"] = False
    if mode == "sso_gate":
        payload["upstream_tls_verify"] = False
    elif "upstream_tls_verify" in payload:
        payload["upstream_tls_verify"] = bool(payload["upstream_tls_verify"])
    app = App(**payload)
    db.add(app)
    db.commit()
    db.refresh(app)

    log_action(
        db,
        actor="system",
        action="app.create",
        target=f"app:{body.slug}",
        ip_address=_client_ip(request),
    )
    return _app_to_out(app)


@router.put("/{slug}", response_model=AppOut)
def update_app(
    slug: str,
    body: AppUpdate,
    request: Request,
    db: Session = Depends(get_db),
):
    app = _get_app_or_404(db, slug)
    updates = body.model_dump(exclude_unset=True)
    mode = normalize_access_mode(updates.get("access_mode", app.access_mode))
    upstream = updates.get("upstream_url", app.upstream_url)
    fqdn = updates.get("public_fqdn", app.public_fqdn)
    field_errors = validate_app_access_fields(mode, upstream or "", fqdn)
    if field_errors:
        raise HTTPException(status_code=422, detail=field_errors)
    if "access_mode" in updates:
        updates["access_mode"] = mode
    if mode != "subdomain_proxy":
        updates["allow_activesync"] = False
    elif "allow_activesync" in updates:
        updates["allow_activesync"] = bool(updates["allow_activesync"])
    if mode == "sso_gate":
        updates["upstream_tls_verify"] = False
    elif "upstream_tls_verify" in updates:
        updates["upstream_tls_verify"] = bool(updates["upstream_tls_verify"])
    for key, value in updates.items():
        setattr(app, key, value)
    app.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(app)

    log_action(
        db,
        actor="system",
        action="app.update",
        target=f"app:{slug}",
        details=updates,
        ip_address=_client_ip(request),
    )
    return _app_to_out(app)


@router.delete("/{slug}", status_code=204)
def delete_app(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
):
    app = _get_app_or_404(db, slug)
    app.enabled = False
    app.updated_at = datetime.now(timezone.utc)
    db.commit()

    log_action(
        db,
        actor="system",
        action="app.delete",
        target=f"app:{slug}",
        ip_address=_client_ip(request),
    )
