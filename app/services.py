"""Application catalogue CRUD and RBAC group management."""

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import get_db
from app.models import App, AppGroup, RBACGroup
from app.security import require_internal_token

router = APIRouter(prefix="/api/apps", tags=["apps"])


class AppCreate(BaseModel):
    slug: str
    label: str
    upstream_url: str
    realm_slug: str | None = None
    access_mode: Literal["sso_gate", "subdomain_proxy", "legacy_path_proxy"] = "sso_gate"
    public_fqdn: str | None = None
    auth_mode: str = "oidc"
    robotic_driver: str | None = None
    healthcheck_url: str | None = None
    enabled: bool = True
    tile_icon: str | None = None


class AppUpdate(BaseModel):
    label: str | None = None
    upstream_url: str | None = None
    realm_slug: str | None = None
    access_mode: Literal["sso_gate", "subdomain_proxy", "legacy_path_proxy"] | None = None
    public_fqdn: str | None = None
    auth_mode: str | None = None
    robotic_driver: str | None = None
    healthcheck_url: str | None = None
    enabled: bool | None = None
    tile_icon: str | None = None


class AppOut(BaseModel):
    slug: str
    label: str
    upstream_url: str
    realm_slug: str | None
    access_mode: str
    public_fqdn: str | None
    auth_mode: str
    robotic_driver: str | None
    healthcheck_url: str | None
    enabled: bool
    tile_icon: str | None

    model_config = {"from_attributes": True}


class GroupLinkBody(BaseModel):
    group_name: str
    realm_slug: str | None = None


class GroupOut(BaseModel):
    name: str
    realm_slug: str | None

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


@router.get("", response_model=list[AppOut])
def list_apps(db: Session = Depends(get_db)):
    apps = db.query(App).filter_by(enabled=True).all()
    return [_app_to_out(app) for app in apps]


@router.get("/{slug}", response_model=AppOut)
def get_app(slug: str, db: Session = Depends(get_db)):
    return _app_to_out(_get_app_or_404(db, slug))


@router.post("", response_model=AppOut, status_code=201)
def create_app(
    body: AppCreate,
    request: Request,
    db: Session = Depends(get_db),
    _token: str = Depends(require_internal_token),
):
    existing = db.query(App).filter_by(slug=body.slug).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"App '{body.slug}' already exists")

    app = App(**body.model_dump())
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
    _token: str = Depends(require_internal_token),
):
    app = _get_app_or_404(db, slug)
    updates = body.model_dump(exclude_unset=True)
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
    _token: str = Depends(require_internal_token),
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


@router.get("/{slug}/groups", response_model=list[GroupOut])
def list_app_groups(
    slug: str,
    db: Session = Depends(get_db),
    _token: str = Depends(require_internal_token),
):
    app = _get_app_or_404(db, slug)
    return [GroupOut.model_validate(link.group) for link in app.groups]


@router.post("/{slug}/groups", response_model=GroupOut, status_code=201)
def add_app_group(
    slug: str,
    body: GroupLinkBody,
    request: Request,
    db: Session = Depends(get_db),
    _token: str = Depends(require_internal_token),
):
    app = _get_app_or_404(db, slug)

    group = db.query(RBACGroup).filter_by(name=body.group_name).first()
    if not group:
        group = RBACGroup(name=body.group_name, realm_slug=body.realm_slug)
        db.add(group)
        db.flush()

    existing = (
        db.query(AppGroup)
        .filter_by(app_id=app.id, group_id=group.id)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Group '{body.group_name}' already linked to app '{slug}'",
        )

    link = AppGroup(app_id=app.id, group_id=group.id)
    db.add(link)
    db.commit()
    db.refresh(group)

    log_action(
        db,
        actor="system",
        action="app.group.add",
        target=f"app:{slug}/group:{body.group_name}",
        ip_address=_client_ip(request),
    )
    return GroupOut.model_validate(group)


@router.delete("/{slug}/groups/{group_name}", status_code=204)
def remove_app_group(
    slug: str,
    group_name: str,
    request: Request,
    db: Session = Depends(get_db),
    _token: str = Depends(require_internal_token),
):
    app = _get_app_or_404(db, slug)
    group = db.query(RBACGroup).filter_by(name=group_name).first()
    if not group:
        raise HTTPException(status_code=404, detail=f"Group '{group_name}' not found")

    link = (
        db.query(AppGroup)
        .filter_by(app_id=app.id, group_id=group.id)
        .first()
    )
    if not link:
        raise HTTPException(
            status_code=404,
            detail=f"Group '{group_name}' not linked to app '{slug}'",
        )

    db.delete(link)
    db.commit()

    log_action(
        db,
        actor="system",
        action="app.group.remove",
        target=f"app:{slug}/group:{group_name}",
        ip_address=_client_ip(request),
    )
