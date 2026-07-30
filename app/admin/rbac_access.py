"""Admin RBAC access grants — members, user search, grant CRUD."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import or_

from app.audit import log_action
from app.bastion.bastion_fields import vault_enabled_for_app
from app.database import get_db
from app.models import AccessGrant, App, BastionAccount, BastionAccountProvisioning, FileResource, RBACGroup, RealmConfig
from app.rbac.grants_service import (
    ACCESS_LEVELS,
    SYSTEM_ROLES,
    AccessGrantCreate,
    build_application_access_view,
    build_grants_matrix,
    compute_effective_grants,
    create_grant,
    delete_grant,
    is_portal_admin_system_grant,
    is_self_portal_admin_grant,
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

_SELF_REVOKE_PORTAL_ADMIN_MSG = "Vous ne pouvez pas retirer votre propre rôle admin"


def _wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "application/json" in accept or request.headers.get("x-requested-with") == "XMLHttpRequest"


def _log_grant_mutation(
    db: Session,
    *,
    actor: str,
    grant,
    request: Request,
    created: bool,
) -> None:
    """Generic grant audit + dedicated portal_admin actions when applicable."""
    generic = "rbac.grant.created" if created else "rbac.grant.deleted"
    details = {
        "subject_type": grant.subject_type,
        "rbac_group_id": grant.rbac_group_id,
        "keycloak_user_id": grant.keycloak_user_id,
        "resource_type": grant.resource_type,
        "application_id": grant.application_id,
        "system_role": grant.system_role,
        "file_id": getattr(grant, "file_id", None),
    }
    if created:
        details["access_level"] = grant.access_level
    log_action(
        db,
        actor=actor,
        action=generic,
        target=f"grant:{grant.id}",
        details=details,
        ip_address=_client_ip(request),
    )
    if is_portal_admin_system_grant(grant):
        log_action(
            db,
            actor=actor,
            action="portal_admin_grant_created" if created else "portal_admin_grant_revoked",
            target=f"grant:{grant.id}",
            details={
                "subject_type": grant.subject_type,
                "rbac_group_id": grant.rbac_group_id,
                "keycloak_user_id": grant.keycloak_user_id,
                "system_role": grant.system_role,
            },
            ip_address=_client_ip(request),
        )


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
    from app.files.service import file_grant_select_options, folder_grant_select_options

    file_options = file_grant_select_options(db)
    folder_options = folder_grant_select_options(db)
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
            file_options=file_options,
            folder_options=folder_options,
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
    group: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.rbac.users_stats_service import (
        connection_anomalies,
        enrich_granted_users,
        fetch_user_directory_stats,
        group_distribution,
    )

    realms = (
        db.query(RealmConfig)
        .filter(
            RealmConfig.enabled.is_(True),
            or_(
                RealmConfig.groups_sync_enabled.is_(True),
                RealmConfig.provisioning_enabled.is_(True),
            ),
        )
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
    enriched_users = enrich_granted_users(
        db, granted_users, group_filter=group, status_filter=status
    )

    # Local bastion-created accounts must stay visible even without AccessGrant and
    # even when the Keycloak picker realm differs (clients vs ar-systems).
    bastion_accounts = (
        db.query(BastionAccount)
        .options(
            joinedload(BastionAccount.realm),
            joinedload(BastionAccount.provisionings).joinedload(
                BastionAccountProvisioning.application
            ),
        )
        .order_by(BastionAccount.created_at.desc())
        .limit(100)
        .all()
    )
    bastion_by_kc: dict[str, BastionAccount] = {}
    for row in bastion_accounts:
        if row.keycloak_user_id:
            bastion_by_kc[row.keycloak_user_id] = row
    for row in (
        db.query(BastionAccount)
        .options(
            joinedload(BastionAccount.provisionings).joinedload(
                BastionAccountProvisioning.application
            ),
        )
        .filter(BastionAccount.keycloak_user_id.is_not(None))
        .all()
    ):
        if row.keycloak_user_id and row.keycloak_user_id not in bastion_by_kc:
            bastion_by_kc[row.keycloak_user_id] = row

    for u in enriched_users:
        linked = bastion_by_kc.get(u.get("keycloak_user_id") or "")
        u["bastion_account_id"] = linked.id if linked else None
        u["bastion_origin"] = linked.origin if linked else None
        u["account_source"] = (
            "bastion" if linked and linked.origin == "bastion" else "keycloak"
        )
        u["realm_id"] = (
            linked.realm_id
            if linked
            else (selected_realm.id if selected_realm else None)
        )
        if linked:
            rows = list(linked.provisionings or [])
            u["provision_ok"] = sum(1 for r in rows if r.status == "success")
            u["provision_failed"] = sum(1 for r in rows if r.status == "failed")
            u["provision_total"] = len(rows)
            pending = linked.pending_application_ids or []
            u["provision_pending"] = len(pending) if isinstance(pending, list) else 0
        else:
            u["provision_ok"] = u["provision_failed"] = u["provision_total"] = 0
            u["provision_pending"] = 0

    bastion_account_for_user = (
        bastion_by_kc.get(keycloak_user_id) if keycloak_user_id else None
    )
    if keycloak_user_id and bastion_account_for_user is None:
        bastion_account_for_user = (
            db.query(BastionAccount)
            .options(
                joinedload(BastionAccount.provisionings).joinedload(
                    BastionAccountProvisioning.application
                ),
            )
            .filter_by(keycloak_user_id=keycloak_user_id)
            .first()
        )

    user_provisionings = []
    user_pending_apps = []
    if bastion_account_for_user is not None:
        user_provisionings = sorted(
            bastion_account_for_user.provisionings or [],
            key=lambda r: (r.application.label if r.application else ""),
        )
        done_ids = {r.application_id for r in user_provisionings}
        pending_ids = bastion_account_for_user.pending_application_ids or []
        if isinstance(pending_ids, list):
            apps_by_id = {a.id: a for a in apps}
            for raw_id in pending_ids:
                try:
                    aid = int(raw_id)
                except (TypeError, ValueError):
                    continue
                if aid not in done_ids and aid in apps_by_id:
                    user_pending_apps.append(apps_by_id[aid])

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

    user_stats = await fetch_user_directory_stats(db, selected_realm, settings)
    anomalies = connection_anomalies(db)
    distribution = group_distribution(db)
    all_groups = db.query(RBACGroup).order_by(RBACGroup.name).all()

    from app.files.service import file_grant_select_options, folder_grant_select_options

    file_options = file_grant_select_options(db)
    folder_options = folder_grant_select_options(db)

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
            file_options=file_options,
            folder_options=folder_options,
            vault_apps=vault_apps,
            granted_users=enriched_users,
            system_roles=SYSTEM_ROLES,
            access_levels=sorted(ACCESS_LEVELS),
            active_tab="users",
            user_stats=user_stats.as_dict(),
            anomalies=anomalies,
            group_distribution=distribution,
            filter_groups=all_groups,
            filter_group=group or "",
            filter_status=status or "tous",
            bastion_accounts=bastion_accounts,
            bastion_account_for_user=bastion_account_for_user,
            user_provisionings=user_provisionings,
            user_pending_apps=user_pending_apps,
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
    # Reserved path segments must never be treated as Keycloak user ids
    # (defence if router registration order regresses).
    if keycloak_user_id in {"new", "search", "accounts"}:
        raise HTTPException(status_code=404, detail="Not Found")
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
    elif data.resource_type == "file" and data.file_id:
        redirect_url = f"/admin/files/{data.file_id}"

    grant = create_grant(db, data, user.email)
    db.commit()

    _log_grant_mutation(
        db,
        actor=user.email,
        grant=grant,
        request=request,
        created=True,
    )

    # Post-grant provisioning hook (spec §5.3) — after the grant commit so a
    # provisioning failure never rolls back the granted right. Explicit result,
    # never silent; user-subject grants toward apps with a provisioning driver.
    provisioning_summary = None
    try:
        from app.rbac.account_service import provision_for_grant

        provisioning_summary = await provision_for_grant(
            db, settings, grant, actor=user.email, ip_address=_client_ip(request)
        )
    except Exception:
        logger.exception("post-grant provisioning hook failed grant_id=%s", grant.id)
        provisioning_summary = {
            "status": "failed",
            "detail": "Erreur interne du hook de provisioning (voir logs serveur)",
        }

    if _wants_json(request):
        payload = {"ok": True, "grant": serialize_grant(grant, db)}
        if provisioning_summary is not None:
            payload["provisioning"] = provisioning_summary
        return JSONResponse(payload)

    response = RedirectResponse(url=redirect_url, status_code=302)
    secret = settings.vault_portal_internal_token or "dev"
    if provisioning_summary is None:
        flash_redirect(response, "Droit accordé.", "success", secret)
    elif provisioning_summary.get("status") == "success":
        flash_redirect(
            response,
            f"Droit accordé. Provisioning {provisioning_summary.get('app_slug')} : succès.",
            "success",
            secret,
        )
    else:
        flash_redirect(
            response,
            "Droit accordé, mais provisioning "
            f"{provisioning_summary.get('app_slug') or ''} : "
            f"{provisioning_summary.get('detail')}",
            "warning",
            secret,
        )
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
    existing = db.query(AccessGrant).filter_by(id=grant_id).first()
    if not existing:
        raise HTTPException(status_code=404, detail="Grant introuvable")

    if is_self_portal_admin_grant(
        existing, actor_keycloak_user_id=user.keycloak_user_id
    ):
        if _wants_json(request) or request.method == "DELETE":
            return JSONResponse(
                {"ok": False, "detail": _SELF_REVOKE_PORTAL_ADMIN_MSG},
                status_code=400,
            )
        response = RedirectResponse(url=redirect_url or "/admin/rbac/users", status_code=302)
        flash_redirect(
            response,
            _SELF_REVOKE_PORTAL_ADMIN_MSG,
            "error",
            settings.vault_portal_internal_token or "dev",
        )
        return response

    grant = delete_grant(db, grant_id)
    if not grant:
        raise HTTPException(status_code=404, detail="Grant introuvable")

    _log_grant_mutation(
        db,
        actor=user.email,
        grant=grant,
        request=request,
        created=False,
    )
    db.commit()

    if redirect_url in ("/admin/rbac", ""):
        if (
            grant.resource_type == "application"
            and grant.application_id
        ):
            redirect_url = f"/admin/rbac/applications/{grant.application_id}"
        elif grant.resource_type == "file" and grant.file_id:
            redirect_url = f"/admin/files/{grant.file_id}"
        elif grant.subject_type == "group" and grant.rbac_group_id:
            redirect_url = f"/admin/rbac/groups/{grant.rbac_group_id}"
        elif grant.subject_type == "user" and grant.keycloak_user_id:
            redirect_url = "/admin/rbac/users"

    if _wants_json(request) or request.method == "DELETE":
        return JSONResponse({"ok": True})

    response = RedirectResponse(url=redirect_url, status_code=302)
    flash_redirect(response, "Droit retiré.", "success", settings.vault_portal_internal_token or "dev")
    return response
