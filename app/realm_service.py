"""Multi-realm OIDC configuration and Nginx export."""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.admin.export import compute_redirect_uri, generate_nginx_realms_conf
from app.audit import log_action
from app.database import get_db
from app.models import RealmConfig
from app.secret_crypto import encrypt_secret
from app.security import require_internal_token
from app.sso_settings import Settings, get_settings

router = APIRouter(prefix="/api/admin/realms", tags=["realms"])


class RealmCreate(BaseModel):
    slug: str
    name: str
    issuer_url: str
    client_id: str
    client_secret: str
    oauth2_proxy_port: int
    scopes: str = "openid profile email"
    is_default: bool = False
    enabled: bool = False

    @field_validator("issuer_url")
    @classmethod
    def validate_issuer_url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("issuer_url must use https")
        return value.rstrip("/")


class RealmOut(BaseModel):
    slug: str
    name: str
    issuer_url: str
    client_id: str
    oauth2_proxy_port: int
    oauth2_proxy_url: str
    redirect_uri: str
    scopes: str
    is_default: bool
    enabled: bool
    last_test_status: str | None = None

    model_config = {"from_attributes": True}


def _exports_path(settings: Settings) -> Path:
    return Path(settings.exports_dir)


def export_nginx_realms_conf(db: Session, settings: Settings) -> Path:
    """Write the nginx realms conf file and return its path."""
    exports_path = _exports_path(settings)
    exports_path.mkdir(parents=True, exist_ok=True)
    output = exports_path / "nginx-portal-realms.conf"
    output.write_text(
        generate_nginx_realms_conf(db, settings),
        encoding="utf-8",
    )
    return output


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "")


@router.get("", response_model=list[RealmOut])
def list_realms(
    db: Session = Depends(get_db),
    _token: str = Depends(require_internal_token),
):
    return db.query(RealmConfig).all()


@router.post("", response_model=RealmOut, status_code=201)
def create_realm(
    body: RealmCreate,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _token: str = Depends(require_internal_token),
):
    existing = db.query(RealmConfig).filter_by(slug=body.slug).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Realm '{body.slug}' already exists")

    port_taken = db.query(RealmConfig).filter_by(oauth2_proxy_port=body.oauth2_proxy_port).first()
    if port_taken:
        raise HTTPException(status_code=409, detail="oauth2_proxy_port already in use")

    if body.is_default:
        db.query(RealmConfig).filter_by(is_default=True).update({"is_default": False})

    if body.enabled:
        raise HTTPException(
            status_code=400,
            detail="Cannot enable realm without successful OIDC test via admin UI",
        )

    realm = RealmConfig(
        slug=body.slug,
        name=body.name,
        issuer_url=body.issuer_url,
        client_id=body.client_id,
        client_secret_encrypted=encrypt_secret(body.client_secret, settings),
        redirect_uri=compute_redirect_uri(body.slug, settings),
        scopes=body.scopes,
        oauth2_proxy_port=body.oauth2_proxy_port,
        is_default=body.is_default,
        enabled=False,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)

    export_nginx_realms_conf(db, settings)
    log_action(
        db,
        actor="system",
        action="realm.create",
        target=f"realm:{body.slug}",
        ip_address=_client_ip(request),
    )
    return realm


@router.delete("/{slug}", status_code=204)
def delete_realm(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _token: str = Depends(require_internal_token),
):
    realm = db.query(RealmConfig).filter_by(slug=slug).first()
    if not realm:
        raise HTTPException(status_code=404, detail=f"Realm '{slug}' not found")
    if realm.is_default:
        raise HTTPException(status_code=400, detail="Cannot delete default realm")
    if realm.enabled:
        raise HTTPException(status_code=400, detail="Cannot delete enabled realm")

    db.delete(realm)
    db.commit()

    export_nginx_realms_conf(db, settings)
    log_action(
        db,
        actor="system",
        action="realm.delete",
        target=f"realm:{slug}",
        ip_address=_client_ip(request),
    )


@router.post("/export")
def export_realms(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _token: str = Depends(require_internal_token),
):
    path = export_nginx_realms_conf(db, settings)
    log_action(
        db,
        actor="system",
        action="realm.export",
        target=str(path),
        ip_address=_client_ip(request),
    )
    return {"status": "ok", "path": str(path)}
