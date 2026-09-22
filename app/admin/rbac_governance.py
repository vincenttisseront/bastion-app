"""RBAC governance — internal Bastion Pro roles × modules matrix."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import get_db
from app.rbac.governance_service import (
    apply_permission_diff,
    create_role,
    get_role,
    integrity_checks,
    list_roles,
    permissions_matrix_for_role,
    serialize_role,
)
from app.web.openapi_responses import (
    RESP_400,
    RESP_401,
    RESP_403,
    RESP_404,
    RESP_409,
    RESP_422,
    RESP_500,
    RESP_503,
)
from app.rbac.permission_seed import seed_governance_rbac
from app.sso_settings import Settings, get_settings
from app.web.flash import flash_redirect
from app.web.templates import render
from app.web.user_context import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-rbac-governance"], dependencies=[Depends(require_admin)])


def _wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "application/json" in accept or request.headers.get("x-requested-with") == "XMLHttpRequest"


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "")


def _mode_is_total(mode: str) -> bool:
    return mode in ("total", "full", "acces_total")


def _resolve_role_for_group_config(db: Session, body: dict, mode: str):
    from app.models import RbacRole
    from app.rbac.permission_seed import SECURITY_ADMIN_ROLE_NAME

    role_name = SECURITY_ADMIN_ROLE_NAME if _mode_is_total(mode) else None
    role_id = body.get("rbac_role_id")
    if role_id:
        return db.query(RbacRole).filter_by(id=int(role_id)).first()
    if role_name:
        return db.query(RbacRole).filter_by(name=role_name).first()
    return None


def _replace_group_rbac_role_grants(
    db: Session,
    *,
    group_id: int,
    role,
    mode: str,
    granted_by: str,
) -> None:
    from app.models import AccessGrant
    from app.rbac.grants_service import AccessGrantCreate, create_grant, delete_grant

    existing = (
        db.query(AccessGrant)
        .filter_by(
            subject_type="group",
            rbac_group_id=group_id,
            resource_type="rbac_role",
        )
        .all()
    )
    for g in existing:
        delete_grant(db, g.id)

    if role is None:
        return
    create_grant(
        db,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group_id,
            resource_type="rbac_role",
            rbac_role_id=role.id,
            access_level="manage" if _mode_is_total(mode) else "view",
        ),
        granted_by=granted_by,
    )


def _apply_group_meta_updates(group, body: dict) -> None:
    if "description" in body:
        group.description = (body.get("description") or "").strip() or None
    if "group_tag" in body:
        group.group_tag = (body.get("group_tag") or "").strip() or None


def _ctx(request: Request, settings: Settings, **extra):
    from app.web.constants import APP_VERSION
    from app.web.flash import base_template_context

    return base_template_context(request, settings, APP_VERSION, **extra)


@router.get("/admin/rbac/governance", responses=RESP_500)
def admin_rbac_governance(
    request: Request,
    role_id: int | None = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    seed_governance_rbac(db)
    db.commit()

    roles = list_roles(db)
    if not roles:
        raise HTTPException(status_code=500, detail="Aucun rôle de gouvernance")

    active = get_role(db, role_id) if role_id else roles[0]
    if active is None:
        active = roles[0]

    matrix = permissions_matrix_for_role(db, active.id)
    db.commit()

    history = []
    from sqlalchemy import desc

    from app.models import AuditLog

    history = (
        db.query(AuditLog)
        .filter(AuditLog.action == "role_permission_updated")
        .filter(AuditLog.target == f"rbac_role:{active.id}")
        .order_by(desc(AuditLog.id))
        .limit(20)
        .all()
    )

    issues = integrity_checks(db)
    last_perm = None
    for row in matrix:
        p = row["permission"]
        if p.get("updated_at") and (
            last_perm is None or (p.get("updated_at") or "") > (last_perm.get("updated_at") or "")
        ):
            last_perm = p

    return render(
        "admin/rbac/governance.html",
        **_ctx(
            request,
            settings,
            roles=[serialize_role(r) for r in roles],
            active_role=serialize_role(active),
            matrix=matrix,
            integrity_issues=issues,
            history=history,
            last_permission_update=last_perm,
            active_tab="governance",
        ),
    )


@router.post("/admin/rbac/roles/{role_id}/permissions")
async def admin_rbac_role_permissions_save(
    role_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    body = await request.json()
    changes = body.get("changes") or []
    try:
        applied = apply_permission_diff(
            db, role_id, changes, actor=user.email or user.username
        )
    except ValueError as exc:
        return JSONResponse({"ok": False, "detail": str(exc)}, status_code=400)

    for item in applied:
        log_action(
            db,
            actor=user.email or user.username,
            action="role_permission_updated",
            target=f"rbac_role:{role_id}",
            details=item,
            ip_address=_client_ip(request),
        )
    db.commit()
    return JSONResponse({"ok": True, "applied": applied})


@router.post("/admin/rbac/roles")
async def admin_rbac_role_create(
    request: Request,
    name: str = Form(...),
    inherits_from_id: str = Form(""),
    is_critical: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    parent_id = int(inherits_from_id) if (inherits_from_id or "").strip().isdigit() else None
    try:
        role = create_role(
            db,
            name=name,
            inherits_from_id=parent_id,
            is_critical=bool(is_critical),
        )
        db.commit()
    except ValueError as exc:
        response = RedirectResponse(url="/admin/rbac/governance", status_code=302)
        flash_redirect(
            response, str(exc), "error", settings.vault_portal_internal_token or "dev"
        )
        return response

    log_action(
        db,
        actor=user.email or user.username,
        action="rbac_role_created",
        target=f"rbac_role:{role.id}",
        details={"name": role.name, "inherits_from_id": parent_id},
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(
        url=f"/admin/rbac/governance?role_id={role.id}", status_code=302
    )
    flash_redirect(
        response, "Rôle créé.", "success", settings.vault_portal_internal_token or "dev"
    )
    return response


@router.post("/admin/rbac/groups/{group_id}/role-config", responses=RESP_404)
async def admin_rbac_group_role_config(
    group_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Assign / replace rbac_role AccessGrant for a group (Total vs Limité shortcut)."""
    from app.models import RBACGroup

    group = db.query(RBACGroup).filter_by(id=group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Groupe introuvable")

    body = await request.json() if _wants_json(request) else dict(await request.form())
    mode = str(body.get("mode") or "limited").strip().lower()
    role = _resolve_role_for_group_config(db, body, mode)
    _replace_group_rbac_role_grants(
        db,
        group_id=group_id,
        role=role,
        mode=mode,
        granted_by=user.email or user.username,
    )
    _apply_group_meta_updates(group, body)

    log_action(
        db,
        actor=user.email or user.username,
        action="group_rbac_config_updated",
        target=f"rbac_group:{group_id}",
        details={
            "mode": mode,
            "rbac_role_id": role.id if role else None,
            "rbac_role_name": role.name if role else None,
        },
        ip_address=_client_ip(request),
    )
    db.commit()

    if _wants_json(request):
        return JSONResponse({"ok": True})
    response = RedirectResponse(url=f"/admin/rbac/groups/{group_id}", status_code=302)
    flash_redirect(
        response,
        "Configuration groupe enregistrée.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response
