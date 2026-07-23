"""Admin RBAC access grants — members, user search, grant CRUD."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.audit import log_action
from app.bastion.bastion_fields import vault_enabled_for_app
from app.database import get_db
from app.models import App, RBACGroup, RealmConfig
from app.rbac.grants_service import (
    ACCESS_LEVELS,
    SYSTEM_ROLES,
    AccessGrantCreate,
    build_application_access_view,
    build_grants_matrix,
    compute_effective_grants,
    create_grant,
    delete_grant,
    list_grants,
    list_users_with_direct_grants,
    serialize_grant,
    serialize_member,
    serialize_user_search_result,
)
from app.rbac.keycloak_admin import (
    fetch_group_members,
    fetch_keycloak_user,
    fetch_user_groups,
    search_keycloak_users_fuzzy,
)
from app.sso_settings import Settings, get_settings
from app.vault.user_app_credential_service import get_user_credential, has_user_override
from app.web.flash import flash_redirect
from app.web.templates import render
from app.web.user_context import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-rbac-access"], dependencies=[Depends(require_admin)])


def _wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "application/json" in accept or request.headers.get("x-requested-with") == "XMLHttpRequest"


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "")


def _ctx(request: Request, settings: Settings, **extra):
    from app.web.constants import APP_VERSION
    from app.web.flash import base_template_context

    return base_template_context(request, settings, APP_VERSION, **extra)


def _realm_for_group(db: Session, group_id: int) -> tuple[RBACGroup, RealmConfig]:
    group = db.query(RBACGroup).filter_by(id=group_id).first()
    if not group or not group.realm_id:
        raise HTTPException(status_code=404, detail="Groupe introuvable")
    realm = db.query(RealmConfig).filter_by(id=group.realm_id).first()
    if not realm:
        raise HTTPException(status_code=404, detail="Realm introuvable pour ce groupe")
    return group, realm


def _realm_or_404(db: Session, realm_id: int) -> RealmConfig:
    realm = db.query(RealmConfig).filter_by(id=realm_id).first()
    if not realm:
        raise HTTPException(status_code=404, detail="Realm introuvable")
    return realm


def _keycloak_error_response(request: Request, exc: ValueError, redirect_url: str):
    if _wants_json(request):
        return JSONResponse({"ok": False, "errors": {"_form": str(exc)}}, status_code=400)
    response = RedirectResponse(url=redirect_url, status_code=302)
    flash_redirect(
        response,
        str(exc),
        "error",
        get_settings().vault_portal_internal_token or "dev",
    )
    return response


@router.get("/admin/rbac/groups/{group_id}")
async def admin_rbac_group_detail(
    group_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    group, realm = _realm_for_group(db, group_id)
    grants = list_grants(db, rbac_group_id=group.id)
    members: list[dict] = []
    members_error: str | None = None

    if group.keycloak_group_id and realm.groups_sync_enabled:
        try:
            raw = await fetch_group_members(realm, group.keycloak_group_id, settings)
            members = [serialize_member(m) for m in raw]
        except ValueError as exc:
            members_error = str(exc)
        except Exception:
            logger.exception("Failed to fetch group members")
            members_error = "Erreur serveur lors de la lecture des membres Keycloak"

    if _wants_json(request):
        return JSONResponse(
            {
                "ok": True,
                "group": {
                    "id": group.id,
                    "name": group.name,
                    "path": group.path,
                    "realm_id": group.realm_id,
                },
                "members": members,
                "members_error": members_error,
                "grants": [serialize_grant(g, db) for g in grants],
            }
        )

    apps = db.query(App).filter_by(enabled=True).order_by(App.label).all()
    return render(
        "admin/rbac/groups_detail.html",
        **_ctx(
            request,
            settings,
            group=group,
            realm=realm,
            members=members,
            members_error=members_error,
            grants=grants,
            grant_rows=[serialize_grant(g, db) for g in grants],
            apps=apps,
            system_roles=SYSTEM_ROLES,
            access_levels=sorted(ACCESS_LEVELS),
        ),
    )


@router.get("/admin/rbac/groups/{group_id}/members")
async def admin_rbac_group_members(
    group_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    group, realm = _realm_for_group(db, group_id)
    if not group.keycloak_group_id:
        raise HTTPException(status_code=400, detail="Groupe sans identifiant Keycloak")
    try:
        raw = await fetch_group_members(realm, group.keycloak_group_id, settings)
    except ValueError as exc:
        return JSONResponse({"ok": False, "errors": {"_form": str(exc)}}, status_code=400)
    return JSONResponse(
        {"ok": True, "members": [serialize_member(m) for m in raw]}
    )


@router.get("/admin/rbac/users/search")
async def admin_rbac_users_search(
    request: Request,
    realm_id: int,
    q: str = "",
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    realm = _realm_or_404(db, realm_id)
    if not realm.groups_sync_enabled:
        return JSONResponse(
            {"ok": False, "errors": {"_form": "Compte de service non configuré pour ce realm"}},
            status_code=400,
        )
    try:
        results = await search_keycloak_users_fuzzy(realm, q, settings, limit=8)
    except ValueError as exc:
        return JSONResponse({"ok": False, "errors": {"_form": str(exc)}}, status_code=400)
    return JSONResponse(
        {
            "ok": True,
            "users": [serialize_user_search_result(u) for u in results],
        }
    )


@router.get("/admin/rbac/users")
async def admin_rbac_users_page(
    request: Request,
    realm_id: int | None = None,
    keycloak_user_id: str | None = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    realms = (
        db.query(RealmConfig)
        .filter_by(groups_sync_enabled=True)
        .order_by(RealmConfig.slug)
        .all()
    )
    selected_realm = None
    if realm_id is not None:
        selected_realm = _realm_or_404(db, realm_id)
    elif realms:
        selected_realm = realms[0]

    kc_user = None
    kc_groups: list[dict] = []
    kc_email_diag: dict | None = None
    direct_grants: list = []
    effective_grants: list[dict] = []
    user_error: str | None = None

    if selected_realm and keycloak_user_id:
        try:
            kc_user = await fetch_keycloak_user(selected_realm, keycloak_user_id, settings)
            if kc_user:
                from app.rbac.oidc_email import keycloak_email_diagnostics

                kc_email_diag = keycloak_email_diagnostics(kc_user)
                raw_groups = await fetch_user_groups(selected_realm, keycloak_user_id, settings)
                kc_groups = raw_groups
                direct_grants = list_grants(db, keycloak_user_id=keycloak_user_id)
                effective_grants = await compute_effective_grants(
                    db, selected_realm, keycloak_user_id, settings
                )
            else:
                user_error = "Utilisateur Keycloak introuvable"
        except ValueError as exc:
            user_error = str(exc)
        except Exception:
            logger.exception("Failed to load user RBAC detail")
            user_error = "Erreur serveur lors du chargement de l'utilisateur"

    apps = db.query(App).filter_by(enabled=True).order_by(App.label).all()
    granted_users = list_users_with_direct_grants(db)

    vault_apps: list[dict] = []
    if keycloak_user_id and (direct_grants or effective_grants):
        apps_by_id = {a.id: a for a in apps}
        seen_slugs: set[str] = set()
        for grant in list(effective_grants) + [
            serialize_grant(g, db) for g in direct_grants
        ]:
            if grant.get("resource_type") != "application":
                continue
            app_id = grant.get("application_id")
            app = apps_by_id.get(app_id) if app_id else None
            if app is None or app.slug in seen_slugs:
                continue
            if not vault_enabled_for_app(app.auth_mode, app.robotic_driver):
                continue
            seen_slugs.add(app.slug)
            override = has_user_override(db, app.slug, keycloak_user_id)
            user_cred = get_user_credential(db, app.slug, keycloak_user_id) if override else None
            vault_apps.append(
                {
                    "slug": app.slug,
                    "label": app.label,
                    "robotic_driver": app.robotic_driver,
                    "credential_mode": app.credential_mode or "shared",
                    "has_override": override,
                    "robotic_username": user_cred.robotic_username if user_cred else None,
                }
            )

    return render(
        "admin/rbac/users.html",
        **_ctx(
            request,
            settings,
            realms=realms,
            selected_realm=selected_realm,
            keycloak_user_id=keycloak_user_id,
            kc_user=kc_user,
            kc_email_diag=kc_email_diag,
            kc_groups=kc_groups,
            direct_grants=[serialize_grant(g, db) for g in direct_grants],
            effective_grants=effective_grants,
            user_error=user_error,
            apps=apps,
            vault_apps=vault_apps,
            granted_users=granted_users,
            system_roles=SYSTEM_ROLES,
            access_levels=sorted(ACCESS_LEVELS),
            active_tab="users",
        ),
    )


@router.get("/admin/rbac/users/{keycloak_user_id}")
async def admin_rbac_user_detail(
    keycloak_user_id: str,
    request: Request,
    realm_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    realm = _realm_or_404(db, realm_id)
    try:
        kc_user = await fetch_keycloak_user(realm, keycloak_user_id, settings)
        if not kc_user:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable")
        kc_groups = await fetch_user_groups(realm, keycloak_user_id, settings)
        direct = list_grants(db, keycloak_user_id=keycloak_user_id)
        effective = await compute_effective_grants(db, realm, keycloak_user_id, settings)
    except ValueError as exc:
        return JSONResponse({"ok": False, "errors": {"_form": str(exc)}}, status_code=400)

    return JSONResponse(
        {
            "ok": True,
            "user": serialize_user_search_result(kc_user),
            "groups": kc_groups,
            "direct_grants": [serialize_grant(g, db) for g in direct],
            "effective_grants": effective,
        }
    )


@router.get("/admin/rbac/applications/{application_id}")
async def admin_rbac_application_detail(
    application_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    app = db.query(App).filter_by(id=application_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application introuvable")

    access = await build_application_access_view(db, application_id, settings)
    db.commit()  # persist refreshed member_count cache when available

    if _wants_json(request):
        return JSONResponse(
            {
                "ok": True,
                "application": {
                    "id": app.id,
                    "slug": app.slug,
                    "label": app.label,
                },
                **access,
            }
        )

    groups = db.query(RBACGroup).order_by(RBACGroup.name).all()
    realms = (
        db.query(RealmConfig)
        .filter_by(groups_sync_enabled=True)
        .order_by(RealmConfig.slug)
        .all()
    )
    return render(
        "admin/rbac/application_detail.html",
        **_ctx(
            request,
            settings,
            application=app,
            grant_rows=access["grants"],
            grant_count=access["grant_count"],
            unique_people_count=access["unique_people_count"],
            people_sources=access["people_sources"],
            groups=groups,
            realms=realms,
            access_levels=sorted(ACCESS_LEVELS),
        ),
    )


@router.get("/admin/rbac/matrix")
def admin_rbac_matrix(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    matrix = build_grants_matrix(db)
    if _wants_json(request):
        return JSONResponse({"ok": True, **matrix})
    return render(
        "admin/rbac/matrix.html",
        **_ctx(request, settings, matrix=matrix, active_tab="matrix"),
    )


@router.get("/admin/rbac/grants")
def admin_rbac_grants_list(
    request: Request,
    rbac_group_id: int | None = None,
    keycloak_user_id: str | None = None,
    application_id: int | None = None,
    db: Session = Depends(get_db),
    _user=Depends(require_admin),
):
    grants = list_grants(
        db,
        rbac_group_id=rbac_group_id,
        keycloak_user_id=keycloak_user_id,
        application_id=application_id,
    )
    return JSONResponse(
        {"ok": True, "grants": [serialize_grant(g, db) for g in grants]}
    )


@router.post("/admin/rbac/grants")
async def admin_rbac_grants_create(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    redirect_url = "/admin/rbac"
    body: dict = {}
    if _wants_json(request) or request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()
    else:
        form = await request.form()
        body = {k: (v if v != "" else None) for k, v in dict(form).items()}
        redirect_url = str(form.get("redirect_url") or redirect_url)

    preferred_redirect = body.get("redirect_url") or redirect_url

    try:
        data = AccessGrantCreate.model_validate(body)
    except ValidationError as exc:
        if _wants_json(request):
            return JSONResponse(
                {"ok": False, "errors": {e["loc"][-1]: e["msg"] for e in exc.errors()}},
                status_code=400,
            )
        response = RedirectResponse(url=str(preferred_redirect), status_code=302)
        flash_redirect(
            response,
            exc.errors()[0]["msg"],
            "error",
            settings.vault_portal_internal_token or "dev",
        )
        return response

    if preferred_redirect and str(preferred_redirect) != "/admin/rbac":
        redirect_url = str(preferred_redirect)
    elif data.subject_type == "group" and data.rbac_group_id:
        group = db.query(RBACGroup).filter_by(id=data.rbac_group_id).first()
        if not group:
            raise HTTPException(status_code=404, detail="Groupe introuvable")
        redirect_url = f"/admin/rbac/groups/{group.id}"
    elif data.subject_type == "user" and data.keycloak_user_id:
        realm_id = body.get("realm_id")
        q = f"?realm_id={realm_id}&keycloak_user_id={data.keycloak_user_id}" if realm_id else ""
        redirect_url = f"/admin/rbac/users{q}"
    elif data.resource_type == "application" and data.application_id:
        redirect_url = f"/admin/rbac/applications/{data.application_id}"

    grant = create_grant(db, data, user.email)
    db.commit()

    target = f"grant:{grant.id}"
    log_action(
        db,
        actor=user.email,
        action="rbac.grant.created",
        target=target,
        details={
            "subject_type": grant.subject_type,
            "rbac_group_id": grant.rbac_group_id,
            "keycloak_user_id": grant.keycloak_user_id,
            "resource_type": grant.resource_type,
            "application_id": grant.application_id,
            "system_role": grant.system_role,
            "access_level": grant.access_level,
        },
        ip_address=_client_ip(request),
    )

    if _wants_json(request):
        return JSONResponse({"ok": True, "grant": serialize_grant(grant, db)})

    response = RedirectResponse(url=redirect_url, status_code=302)
    flash_redirect(response, "Droit accordé.", "success", settings.vault_portal_internal_token or "dev")
    return response


@router.delete("/admin/rbac/grants/{grant_id}")
@router.post("/admin/rbac/grants/{grant_id}/delete")
def admin_rbac_grants_delete(
    grant_id: int,
    request: Request,
    redirect_url: str = Form("/admin/rbac"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    grant = delete_grant(db, grant_id)
    if not grant:
        raise HTTPException(status_code=404, detail="Grant introuvable")

    log_action(
        db,
        actor=user.email,
        action="rbac.grant.deleted",
        target=f"grant:{grant_id}",
        details={
            "subject_type": grant.subject_type,
            "rbac_group_id": grant.rbac_group_id,
            "keycloak_user_id": grant.keycloak_user_id,
            "resource_type": grant.resource_type,
            "application_id": grant.application_id,
            "system_role": grant.system_role,
        },
        ip_address=_client_ip(request),
    )
    db.commit()

    if redirect_url in ("/admin/rbac", ""):
        if (
            grant.resource_type == "application"
            and grant.application_id
        ):
            redirect_url = f"/admin/rbac/applications/{grant.application_id}"
        elif grant.subject_type == "group" and grant.rbac_group_id:
            redirect_url = f"/admin/rbac/groups/{grant.rbac_group_id}"
        elif grant.subject_type == "user" and grant.keycloak_user_id:
            redirect_url = "/admin/rbac/users"

    if _wants_json(request) or request.method == "DELETE":
        return JSONResponse({"ok": True})

    response = RedirectResponse(url=redirect_url, status_code=302)
    flash_redirect(response, "Droit retiré.", "success", settings.vault_portal_internal_token or "dev")
    return response
