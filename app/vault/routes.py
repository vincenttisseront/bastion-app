"""Admin API routes for application vault credentials."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import get_db
from app.security import require_internal_token
from app.services import get_app_by_slug_or_404
from app.sso_settings import Settings, get_settings
from app.testing_framework.throttle import throttle_retry_after
from app.vault.app_credential_service import (
    EncryptionNotConfiguredError,
    VaultError,
    deactivate_app_credential,
    get_app_credential,
    set_app_credential,
)
from app.vault.credential_connection_test import (
    credential_test_legacy_response,
    test_app_credential_connection,
)

router = APIRouter(prefix="/api/admin/apps", tags=["admin-vault"])


class CredentialSetBody(BaseModel):
    robotic_username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class CredentialOut(BaseModel):
    robotic_username: str
    created_at: datetime | None
    rotated_at: datetime | None
    is_active: bool


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "")


def _credential_out(cred) -> CredentialOut:
    return CredentialOut(
        robotic_username=cred.robotic_username,
        created_at=cred.created_at,
        rotated_at=cred.rotated_at,
        is_active=cred.is_active,
    )


@router.post("/{slug}/credential", response_model=CredentialOut)
def create_or_replace_credential(
    slug: str,
    body: CredentialSetBody,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _token: str = Depends(require_internal_token),
):
    get_app_by_slug_or_404(db, slug)
    try:
        cred = set_app_credential(
            db,
            slug,
            body.robotic_username.strip(),
            body.password,
            settings,
            actor="system",
            ip_address=_client_ip(request),
        )
    except EncryptionNotConfiguredError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except VaultError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _credential_out(cred)


@router.get("/{slug}/credential", response_model=CredentialOut)
def read_credential(
    slug: str,
    db: Session = Depends(get_db),
    _token: str = Depends(require_internal_token),
):
    get_app_by_slug_or_404(db, slug)
    cred = get_app_credential(db, slug)
    if cred is None:
        raise HTTPException(status_code=404, detail=f"No credential for app '{slug}'")
    return _credential_out(cred)


@router.delete("/{slug}/credential", status_code=204)
def delete_credential(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    _token: str = Depends(require_internal_token),
):
    get_app_by_slug_or_404(db, slug)
    deactivate_app_credential(
        db,
        slug,
        actor="system",
        ip_address=_client_ip(request),
    )
    return None


@router.post("/{slug}/credential/test")
async def test_credential(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _token: str = Depends(require_internal_token),
):
    if wait := throttle_retry_after("app_credential", slug, min_interval_seconds=5):
        return JSONResponse(
            {"ok": False, "error": f"Trop de tests — réessayez dans {wait:.0f}s"},
            status_code=429,
        )

    app = get_app_by_slug_or_404(db, slug)
    result = await test_app_credential_connection(db, app, settings)
    log_action(
        db,
        actor="system",
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
