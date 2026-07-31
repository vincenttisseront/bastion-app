"""Admin endpoints for RBAC groups import from Keycloak."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.admin.throttling import check_sync_rate_limit
from app.audit import log_action
from app.database import get_db
from app.models import RBACGroup, RealmConfig
from app.rbac.keycloak_admin import sync_keycloak_groups
from app.sso_settings import Settings, get_settings
from app.web.flash import flash_redirect
from app.web.user_context import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-rbac"], dependencies=[Depends(require_admin)])


def _wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "application/json" in accept or request.headers.get("x-requested-with") == "XMLHttpRequest"


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "")


@router.get("/admin/rbac/groups")
def admin_rbac_groups_list(
    request: Request,
    realm_id: int | None = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    query = db.query(RBACGroup)
    if realm_id is not None:
        query = query.filter(RBACGroup.realm_id == realm_id)
    groups = query.order_by(RBACGroup.name).all()
    if _wants_json(request):
        return JSONResponse(
            {
                "ok": True,
                "groups": [
                    {
                        "id": g.id,
                        "name": g.name,
                        "path": g.path,
                        "realm_id": g.realm_id,
                        "realm_slug": g.realm_slug,
                        "keycloak_group_id": g.keycloak_group_id,
                        "member_count": g.member_count,
                        "synced_at": g.synced_at.isoformat() if g.synced_at else None,
                    }
                    for g in groups
                ],
            }
        )
    raise HTTPException(status_code=406, detail="Only JSON supported for this endpoint")


@router.post("/admin/rbac/groups/sync/{realm_id}")
async def admin_rbac_groups_sync(
    realm_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    realm = db.query(RealmConfig).filter_by(id=realm_id).first()
    if not realm:
        raise HTTPException(status_code=404)

    if wait := check_sync_rate_limit(f"rbac-sync:{realm_id}"):
        msg = f"Trop de synchronisations — réessayez dans {wait:.0f}s"
        if _wants_json(request):
            return JSONResponse({"ok": False, "errors": {"_form": msg}}, status_code=429)
        response = RedirectResponse(url="/admin/rbac", status_code=302)
        flash_redirect(response, msg, "error", settings.vault_portal_internal_token or "dev")
        return response

    try:
        result = await sync_keycloak_groups(realm, db, settings)
        db.commit()
    except ValueError as exc:
        db.rollback()
        msg = str(exc) or "Erreur de synchronisation"
        realm.last_groups_sync_status = "error"
        realm.last_groups_sync_error = msg
        db.commit()
        if _wants_json(request):
            return JSONResponse({"ok": False, "errors": {"_form": msg}}, status_code=400)
        response = RedirectResponse(url="/admin/rbac", status_code=302)
        flash_redirect(response, msg, "error", settings.vault_portal_internal_token or "dev")
        return response
    except Exception:
        db.rollback()
        logger.exception("RBAC groups sync failed")
        msg = "Erreur serveur pendant la synchronisation des groupes"
        realm.last_groups_sync_status = "error"
        realm.last_groups_sync_error = msg
        db.commit()
        if _wants_json(request):
            return JSONResponse({"ok": False, "errors": {"_form": msg}}, status_code=500)
        response = RedirectResponse(url="/admin/rbac", status_code=302)
        flash_redirect(response, msg, "error", settings.vault_portal_internal_token or "dev")
        return response

    log_action(
        db,
        actor=user.email,
        action="rbac.groups.sync",
        target=realm.slug,
        details={k: result.get(k) for k in ("status", "imported", "updated", "orphaned")},
        ip_address=_client_ip(request),
    )

    if _wants_json(request):
        return JSONResponse({"ok": True, **result})

    response = RedirectResponse(url="/admin/rbac", status_code=302)
    flash_redirect(
        response,
        f"Synchronisation groupes OK "
        f"({result.get('imported', 0)} nouveaux groupes, "
        f"{result.get('updated', 0)} mis à jour, "
        f"{result.get('orphaned', 0)} orphelins) — "
        f"les membres Keycloak ne sont pas importés ici.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response

