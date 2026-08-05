"""Admin endpoints for RBAC groups import from Keycloak."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.admin.throttling import check_sync_rate_limit
from app.audit import log_action
from app.database import get_db
from app.models import RBACGroup, RealmConfig
from app.rbac.groups_service import GroupNotEmptyError, delete_empty_rbac_group
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


def _safe_redirect_url(raw: str | None, fallback: str) -> str:
    value = (raw or "").strip()
    if value.startswith("/admin/") and "://" not in value and "\\" not in value:
        return value
    return fallback


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
        details={
            k: result.get(k)
            for k in (
                "status",
                "imported",
                "updated",
                "orphaned",
                "skipped",
                "members_refreshed",
                "members_total",
            )
        },
        ip_address=_client_ip(request),
    )

    if _wants_json(request):
        return JSONResponse({"ok": True, **result})

    parts = [
        f"{result.get('imported', 0)} nouveaux",
        f"{result.get('updated', 0)} mis à jour",
        f"{result.get('orphaned', 0)} orphelins",
    ]
    if result.get("skipped"):
        parts.append(f"{result.get('skipped')} filtrés")
    members_bit = ""
    if result.get("members_refreshed"):
        members_bit = (
            f" · effectifs Keycloak : {result.get('members_total', 0)} membre(s) "
            f"sur {result.get('members_refreshed')} groupe(s)"
        )
    else:
        members_bit = (
            " · effectifs non relus (renseignez le filtre « Groupes à synchroniser » "
            "sur la fiche realm pour compter les membres)"
        )

    response = RedirectResponse(url="/admin/rbac", status_code=302)
    flash_redirect(
        response,
        f"Synchronisation groupes OK ({', '.join(parts)}){members_bit}.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@router.post("/admin/rbac/groups/{group_id}/delete")
async def admin_rbac_group_delete(
    group_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    redirect_url: str | None = Form(None),
    force_local: str | None = Form(None),
):
    """Delete an empty group in Keycloak + Bastion (members must be zero)."""
    group = db.query(RBACGroup).filter_by(id=group_id).first()
    if not group or not group.realm_id:
        raise HTTPException(status_code=404, detail="Groupe introuvable")
    realm = db.query(RealmConfig).filter_by(id=group.realm_id).first()
    if not realm:
        raise HTTPException(status_code=404, detail="Realm introuvable pour ce groupe")

    fallback = "/admin/rbac"
    dest = _safe_redirect_url(redirect_url, fallback)
    force = (force_local or "").strip().lower() in ("1", "true", "on", "yes")
    group_name = group.name

    try:
        result = await delete_empty_rbac_group(
            db,
            settings,
            group=group,
            realm=realm,
            actor=user.email,
            ip_address=_client_ip(request),
            force_local=force,
        )
        db.commit()
    except GroupNotEmptyError as exc:
        db.rollback()
        msg = str(exc)
        if _wants_json(request):
            return JSONResponse({"ok": False, "errors": {"_form": msg}}, status_code=409)
        response = RedirectResponse(
            url=_safe_redirect_url(redirect_url, f"/admin/rbac/groups/{group_id}"),
            status_code=302,
        )
        flash_redirect(
            response, msg, "error", settings.vault_portal_internal_token or "dev"
        )
        return response
    except ValueError as exc:
        db.rollback()
        msg = str(exc) or "Échec de la suppression du groupe"
        if _wants_json(request):
            return JSONResponse({"ok": False, "errors": {"_form": msg}}, status_code=400)
        response = RedirectResponse(
            url=_safe_redirect_url(redirect_url, f"/admin/rbac/groups/{group_id}"),
            status_code=302,
        )
        flash_redirect(
            response, msg, "error", settings.vault_portal_internal_token or "dev"
        )
        return response
    except Exception:
        db.rollback()
        logger.exception("RBAC group delete failed group_id=%s", group_id)
        msg = "Erreur serveur pendant la suppression du groupe"
        if _wants_json(request):
            return JSONResponse({"ok": False, "errors": {"_form": msg}}, status_code=500)
        response = RedirectResponse(
            url=_safe_redirect_url(redirect_url, f"/admin/rbac/groups/{group_id}"),
            status_code=302,
        )
        flash_redirect(
            response, msg, "error", settings.vault_portal_internal_token or "dev"
        )
        return response

    if _wants_json(request):
        return JSONResponse({"ok": True, **result})

    if dest.rstrip("/").endswith(f"/groups/{group_id}"):
        dest = fallback
    bits = ["Bastion"]
    if result.get("keycloak_group_id"):
        bits.insert(0, "Keycloak")
    response = RedirectResponse(url=dest, status_code=302)
    flash_redirect(
        response,
        f"Groupe « {group_name} » supprimé ({' + '.join(bits)}).",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response

