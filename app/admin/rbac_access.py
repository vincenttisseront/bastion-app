"""Admin RBAC access grants — members, user search, grant CRUD."""

from __future__ import annotations

import logging

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, or_

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
from app.rbac.groups_service import group_has_local_children
from app.rbac.keycloak_admin import (
    fetch_group_members,
    fetch_keycloak_user,
    fetch_user_groups,
    search_keycloak_users_fuzzy,
)
from app.sso_settings import Settings, get_settings
from app.vault.app_credential_service import VaultError
from app.vault.group_app_credential_service import (
    add_group_credential_exclusion,
    delete_group_credential,
    list_group_credentials,
    remove_group_credential_exclusion,
    set_group_credential,
)
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


def build_vault_apps_for_user(
    db: Session,
    *,
    keycloak_user_id: str | None,
    apps: list[App],
    grant_rows: list[dict] | None = None,
    extra_app_slugs: set[str] | None = None,
) -> list[dict]:
    """Vault rows for admin UI — apps from grants and/or explicit slug set (provisioning)."""
    if not keycloak_user_id:
        return []
    apps_by_id = {a.id: a for a in apps}
    apps_by_slug = {a.slug: a for a in apps}
    seen_slugs: set[str] = set()
    vault_apps: list[dict] = []

    def _append(app: App) -> None:
        if app.slug in seen_slugs:
            return
        override = has_user_override(db, app.slug, keycloak_user_id)
        from_extra = app.slug in (extra_app_slugs or set())
        if not vault_enabled_for_app(app.auth_mode, app.robotic_driver):
            if not (from_extra and override):
                return
        seen_slugs.add(app.slug)
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

    for grant in grant_rows or []:
        if grant.get("resource_type") != "application":
            continue
        app_id = grant.get("application_id")
        app = apps_by_id.get(app_id) if app_id else None
        if app is not None:
            _append(app)

    for slug in extra_app_slugs or set():
        app = apps_by_slug.get(slug)
        if app is not None:
            _append(app)
        else:
            # Orphan credential / unknown app — still surface username if present
            if slug in seen_slugs:
                continue
            override = has_user_override(db, slug, keycloak_user_id)
            if not override:
                continue
            seen_slugs.add(slug)
            user_cred = get_user_credential(db, slug, keycloak_user_id)
            vault_apps.append(
                {
                    "slug": slug,
                    "label": slug,
                    "robotic_driver": None,
                    "credential_mode": "shared",
                    "has_override": True,
                    "robotic_username": user_cred.robotic_username if user_cred else None,
                }
            )

    vault_apps.sort(key=lambda r: (r.get("label") or r["slug"]).lower())
    return vault_apps


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


def _safe_redirect_url(raw: str | None, fallback: str) -> str:
    """Only allow same-origin relative admin paths (open-redirect guard)."""
    value = (raw or "").strip()
    if value.startswith("/admin/") and "://" not in value and "\\" not in value:
        return value
    return fallback


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
            # Keep cached count coherent with live Keycloak membership.
            if group.member_count != len(members):
                group.member_count = len(members)
                db.commit()
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
    vault_apps = [
        a
        for a in apps
        if vault_enabled_for_app(a.auth_mode, a.robotic_driver)
    ]
    group_credentials = list_group_credentials(db, group.id)
    from app.files.service import file_grant_select_options, folder_grant_select_options

    file_options = file_grant_select_options(db)
    folder_options = folder_grant_select_options(db)
    # Empty = no live/cached members and no local subgroups (grants/credentials cascade).
    if members_error:
        can_delete_group = False
    elif group.keycloak_group_id and realm.groups_sync_enabled:
        can_delete_group = len(members) == 0 and not group_has_local_children(db, group)
    else:
        can_delete_group = (
            (group.member_count or 0) == 0
            and len(members) == 0
            and not group_has_local_children(db, group)
        )
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
            vault_apps=vault_apps,
            group_credentials=group_credentials,
            file_options=file_options,
            folder_options=folder_options,
            system_roles=SYSTEM_ROLES,
            access_levels=sorted(ACCESS_LEVELS),
            can_delete_group=can_delete_group,
        ),
    )


@router.post("/admin/rbac/groups/{group_id}/credentials")
async def admin_rbac_group_credential_set(
    group_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    app_slug: str = Form(...),
    robotic_username: str = Form(...),
    password: str = Form(""),
    priority: int = Form(100),
):
    group, _realm = _realm_for_group(db, group_id)
    secret = settings.vault_portal_internal_token or "dev"
    fallback = f"/admin/rbac/groups/{group.id}#comptes"
    try:
        cred = set_group_credential(
            db,
            rbac_group_id=group.id,
            app_slug=app_slug,
            robotic_username=robotic_username,
            plain_password=password,
            settings=settings,
            priority=priority,
            actor=user.email,
            ip_address=_client_ip(request),
        )
    except VaultError as exc:
        if _wants_json(request):
            return JSONResponse(
                {"ok": False, "errors": {"_form": str(exc)}}, status_code=400
            )
        response = RedirectResponse(url=fallback, status_code=302)
        flash_redirect(response, str(exc), "error", secret)
        return response

    if _wants_json(request):
        return JSONResponse(
            {
                "ok": True,
                "credential_id": cred.id,
                "app_slug": cred.app_slug,
                "robotic_username": cred.robotic_username,
                "priority": cred.priority,
            }
        )
    response = RedirectResponse(url=fallback, status_code=302)
    flash_redirect(
        response,
        f"Compte partagé enregistré pour {cred.app_slug} ({cred.robotic_username}).",
        "success",
        secret,
    )
    return response


@router.post("/admin/rbac/groups/{group_id}/credentials/{credential_id}/delete")
async def admin_rbac_group_credential_delete(
    group_id: int,
    credential_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    group, _realm = _realm_for_group(db, group_id)
    secret = settings.vault_portal_internal_token or "dev"
    fallback = f"/admin/rbac/groups/{group.id}#comptes"
    cred = next(
        (c for c in list_group_credentials(db, group.id) if c.id == credential_id),
        None,
    )
    if cred is None:
        raise HTTPException(status_code=404, detail="Compte groupe introuvable")
    delete_group_credential(
        db,
        credential_id,
        actor=user.email,
        ip_address=_client_ip(request),
    )
    if _wants_json(request):
        return JSONResponse({"ok": True})
    response = RedirectResponse(url=fallback, status_code=302)
    flash_redirect(response, "Compte partagé du groupe supprimé.", "success", secret)
    return response


@router.post("/admin/rbac/groups/{group_id}/credentials/{credential_id}/exclusions")
async def admin_rbac_group_credential_exclusion_add(
    group_id: int,
    credential_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    keycloak_user_id: str = Form(...),
):
    group, _realm = _realm_for_group(db, group_id)
    secret = settings.vault_portal_internal_token or "dev"
    fallback = f"/admin/rbac/groups/{group.id}#comptes"
    cred = next(
        (c for c in list_group_credentials(db, group.id) if c.id == credential_id),
        None,
    )
    if cred is None:
        raise HTTPException(status_code=404, detail="Compte groupe introuvable")
    try:
        add_group_credential_exclusion(
            db,
            credential_id,
            keycloak_user_id,
            actor=user.email,
            ip_address=_client_ip(request),
        )
    except VaultError as exc:
        if _wants_json(request):
            return JSONResponse(
                {"ok": False, "errors": {"_form": str(exc)}}, status_code=400
            )
        response = RedirectResponse(url=fallback, status_code=302)
        flash_redirect(response, str(exc), "error", secret)
        return response

    if _wants_json(request):
        return JSONResponse({"ok": True})
    response = RedirectResponse(url=fallback, status_code=302)
    flash_redirect(
        response,
        "Utilisateur exclu du compte partagé — configurez un compte individuel.",
        "success",
        secret,
    )
    return response


@router.post(
    "/admin/rbac/groups/{group_id}/credentials/{credential_id}/exclusions/{keycloak_user_id}/delete"
)
async def admin_rbac_group_credential_exclusion_remove(
    group_id: int,
    credential_id: int,
    keycloak_user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    group, _realm = _realm_for_group(db, group_id)
    secret = settings.vault_portal_internal_token or "dev"
    fallback = f"/admin/rbac/groups/{group.id}#comptes"
    cred = next(
        (c for c in list_group_credentials(db, group.id) if c.id == credential_id),
        None,
    )
    if cred is None:
        raise HTTPException(status_code=404, detail="Compte groupe introuvable")
    remove_group_credential_exclusion(
        db,
        credential_id,
        keycloak_user_id,
        actor=user.email,
        ip_address=_client_ip(request),
    )
    if _wants_json(request):
        return JSONResponse({"ok": True})
    response = RedirectResponse(url=fallback, status_code=302)
    flash_redirect(response, "Exclusion retirée.", "success", secret)
    return response


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
    list_tab: str | None = None,
    q: str | None = None,
    page: int = 1,
    page_size: int | None = None,
    groups_q: str | None = None,
    groups_page: int = 1,
    groups_include_empty: str | None = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.rbac.users_list_service import (
        DEFAULT_PAGE_SIZE,
        clamp_page_size,
        filter_import_users,
        paginate_list,
        query_bastion_accounts,
    )
    from app.rbac.users_stats_service import (
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

    # Deep-link to a user → dedicated fiche (no parent RBAC tabs on that page).
    if keycloak_user_id and selected_realm is not None:
        return RedirectResponse(
            url=(
                f"/admin/rbac/users/view?realm_id={selected_realm.id}"
                f"&keycloak_user_id={keycloak_user_id}"
            ),
            status_code=302,
        )

    page_size = clamp_page_size(page_size if page_size is not None else DEFAULT_PAGE_SIZE)
    search_q = (q or "").strip()

    apps = db.query(App).filter_by(enabled=True).order_by(App.label).all()
    granted_users = list_users_with_direct_grants(db)
    enriched_users = enrich_granted_users(
        db, granted_users, group_filter=group, status_filter=status
    )

    bastion_by_kc: dict[str, BastionAccount] = {}
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
        if row.keycloak_user_id:
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

    import_users_all = [
        u for u in enriched_users if u.get("account_source") != "bastion"
    ]
    import_users_filtered = filter_import_users(import_users_all, q=search_q)

    bastion_count = db.query(func.count(BastionAccount.id)).scalar() or 0
    tab = (list_tab or "").strip().lower()
    if tab not in {"bastion", "keycloak", "open"}:
        if bastion_count:
            tab = "bastion"
        elif import_users_all:
            tab = "keycloak"
        else:
            tab = "open"

    # Bastion tab lists all realms (cross-realm create). realm_id only drives
    # Keycloak stats / Recherche Keycloak picker.
    bastion_accounts: list[BastionAccount] = []
    import_users: list[dict] = []
    list_meta: dict = {
        "total": 0,
        "page": 1,
        "page_size": page_size,
        "total_pages": 1,
    }
    if tab == "bastion":
        bastion_accounts, list_meta = query_bastion_accounts(
            db,
            q=search_q,
            realm_id=None,
            group_name=group,
            status_filter=status,
            page=page,
            page_size=page_size,
        )
    elif tab == "keycloak":
        import_users, list_meta = paginate_list(
            import_users_filtered, page=page, page_size=page_size
        )

    user_stats = await fetch_user_directory_stats(db, selected_realm, settings)

    kc_search_hits: list[dict] = []
    kc_search_error: str | None = None
    if search_q and len(search_q) >= 2 and selected_realm is not None:
        try:
            from app.rbac.keycloak_admin import search_keycloak_users
            from app.rbac.grants_service import serialize_user_search_result

            raw_hits = await search_keycloak_users(
                selected_realm, search_q, settings, max_results=20
            )
            kc_search_hits = [serialize_user_search_result(u) for u in raw_hits]
        except ValueError as exc:
            kc_search_error = str(exc)
        except Exception:
            logger.exception("Keycloak user search failed on users page")
            kc_search_error = "Recherche Keycloak indisponible"

    include_empty = (groups_include_empty or "").strip().lower() in (
        "1",
        "true",
        "on",
        "yes",
    )
    distribution = group_distribution(
        db,
        q=groups_q,
        include_empty=include_empty,
        page=groups_page,
        page_size=25,
    )
    # Facet filter: only non-empty groups (+ keep current selection visible).
    filter_groups_q = (
        db.query(RBACGroup)
        .filter(func.coalesce(RBACGroup.member_count, 0) > 0)
        .order_by(RBACGroup.name)
    )
    filter_groups = filter_groups_q.all()
    if group:
        selected_g = db.query(RBACGroup).filter_by(name=group).first()
        if selected_g and all(g.id != selected_g.id for g in filter_groups):
            filter_groups = [selected_g, *filter_groups]

    bulk_groups = (
        db.query(RBACGroup)
        .filter(RBACGroup.keycloak_group_id.is_not(None))
        .order_by(RBACGroup.name)
        .limit(500)
        .all()
    )

    from app.files.service import file_grant_select_options, folder_grant_select_options

    file_options = file_grant_select_options(db)
    folder_options = folder_grant_select_options(db)

    def _users_qs(**overrides: object) -> str:
        params: dict[str, object] = {}
        if selected_realm is not None:
            params["realm_id"] = selected_realm.id
        if search_q:
            params["q"] = search_q
        if group:
            params["group"] = group
        if status and status != "tous":
            params["status"] = status
        if page_size != DEFAULT_PAGE_SIZE:
            params["page_size"] = page_size
        params["list_tab"] = tab
        params["page"] = list_meta.get("page", 1)
        gq = (groups_q or "").strip()
        if gq:
            params["groups_q"] = gq
        if include_empty:
            params["groups_include_empty"] = "1"
        gp = distribution.get("list_meta", {}).get("page", 1)
        if gp and int(gp) > 1:
            params["groups_page"] = gp
        params.update(overrides)
        # Drop empty / None
        clean = {k: v for k, v in params.items() if v is not None and v != ""}
        return urlencode(clean)

    return render(
        "admin/rbac/users.html",
        **_ctx(
            request,
            settings,
            realms=realms,
            selected_realm=selected_realm,
            keycloak_user_id=None,
            kc_user=None,
            kc_email_diag=None,
            kc_groups=[],
            direct_grants=[],
            effective_grants=[],
            user_error=None,
            apps=apps,
            file_options=file_options,
            folder_options=folder_options,
            vault_apps=[],
            granted_users=enriched_users,
            import_users=import_users,
            import_users_total=len(import_users_all),
            system_roles=SYSTEM_ROLES,
            access_levels=sorted(ACCESS_LEVELS),
            active_tab="users",
            list_tab=tab,
            user_stats=user_stats.as_dict(),
            group_distribution=distribution,
            filter_groups=filter_groups,
            bulk_groups=bulk_groups,
            filter_group=group or "",
            filter_status=status or "tous",
            filter_q=search_q,
            list_meta=list_meta,
            users_qs=_users_qs,
            kc_search_hits=kc_search_hits,
            kc_search_error=kc_search_error,
            bastion_accounts=bastion_accounts,
            bastion_accounts_total=int(bastion_count),
            bastion_account_for_user=None,
            user_provisionings=[],
            user_pending_apps=[],
            directory_users=[],
            directory_source=None,
            directory_error=None,
        ),
    )


@router.post("/admin/rbac/users/bulk/groups")
async def admin_rbac_users_bulk_groups(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    action: str = Form(...),
    group_id: int = Form(...),
    account_ids: list[int] | None = Form(None),
    select_all_matching: str = Form(""),
    q: str = Form(""),
    realm_id: int | None = Form(None),
    group: str = Form(""),
    status: str = Form("tous"),
    redirect_url: str = Form("/admin/rbac/users?list_tab=bastion"),
):
    """Bulk add/remove bastion accounts to/from one Keycloak-synced group."""
    from app.rbac.account_service import AccountCreationError
    from app.rbac.users_bulk_service import (
        bulk_assign_or_remove_groups,
        resolve_bastion_account_ids,
    )

    secret = settings.vault_portal_internal_token or "dev"
    fallback = "/admin/rbac/users?list_tab=bastion"
    act = (action or "").strip().lower()
    if act not in {"add", "remove"}:
        response = RedirectResponse(
            url=_safe_redirect_url(redirect_url, fallback), status_code=302
        )
        flash_redirect(response, "Action bulk invalide.", "error", secret)
        return response

    ids = resolve_bastion_account_ids(
        db,
        account_ids=account_ids or [],
        select_all_matching=(select_all_matching or "").lower()
        in ("1", "true", "on", "yes"),
        q=q,
        realm_id=realm_id,
        group_name=group or None,
        status_filter=status,
    )
    try:
        result = await bulk_assign_or_remove_groups(
            db,
            settings,
            account_ids=ids,
            group_id=group_id,
            action=act,  # type: ignore[arg-type]
            actor=user.email,
            ip_address=_client_ip(request),
        )
    except AccountCreationError as exc:
        response = RedirectResponse(
            url=_safe_redirect_url(redirect_url, fallback), status_code=302
        )
        flash_redirect(response, str(exc), "error", secret)
        return response

    verb = "ajoutés à" if act == "add" else "retirés de"
    msg = (
        f"{result['ok_count']} utilisateur(s) {verb} « {result['group']} »."
    )
    if result["error_count"]:
        msg += f" {result['error_count']} échec(s)."
    response = RedirectResponse(
        url=_safe_redirect_url(redirect_url, fallback), status_code=302
    )
    flash_redirect(
        response,
        msg,
        "warning" if result["error_count"] else "success",
        secret,
    )
    return response


@router.get("/admin/rbac/users/export.csv")
async def admin_rbac_users_export_csv(
    request: Request,
    q: str | None = None,
    realm_id: int | None = None,
    group: str | None = None,
    status: str | None = None,
    ids: str | None = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """CSV export of bastion accounts (filter or comma-separated ids)."""
    from fastapi.responses import Response as FastAPIResponse

    from app.rbac.users_bulk_service import bastion_accounts_csv

    account_ids: list[int] | None = None
    if ids:
        account_ids = []
        for part in ids.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                account_ids.append(int(part))
            except ValueError:
                continue

    csv_body = bastion_accounts_csv(
        db,
        q=q,
        realm_id=realm_id,
        group_name=group,
        status_filter=status,
        account_ids=account_ids,
    )
    log_action(
        db,
        actor=user.email,
        action="users.export_csv",
        details={
            "q": q or "",
            "realm_id": realm_id,
            "group": group or "",
            "status": status or "",
            "ids_count": len(account_ids or []),
        },
        ip_address=_client_ip(request),
    )
    db.commit()
    return FastAPIResponse(
        content=csv_body,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="bastion-users.csv"',
        },
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
    if keycloak_user_id in {"new", "search", "accounts", "view", "bulk", "export.csv"}:
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
    content_type = (request.headers.get("content-type") or "").lower()
    # Parse by Content-Type only — never call request.json() on multipart/form-data
    # (the modal used to send FormData with Accept: application/json).
    if "application/json" in content_type:
        try:
            raw = await request.json()
        except Exception:
            logger.exception("grant create: invalid JSON body")
            if _wants_json(request):
                return JSONResponse(
                    {"ok": False, "errors": {"_form": "Corps JSON invalide"}},
                    status_code=400,
                )
            raise HTTPException(status_code=400, detail="Corps JSON invalide")
        body = raw if isinstance(raw, dict) else {}
    else:
        form = await request.form()
        body = {}
        for k, v in dict(form).items():
            if v is None or v == "":
                continue
            if hasattr(v, "filename"):
                continue
            body[k] = v
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

    granted_by = (getattr(user, "email", None) or getattr(user, "username", None) or "admin").strip()
    if not granted_by:
        granted_by = "admin"

    try:
        grant = create_grant(db, data, granted_by)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("grant create failed subject=%s resource=%s", data.subject_type, data.resource_type)
        if _wants_json(request):
            return JSONResponse(
                {"ok": False, "errors": {"_form": "Impossible d’enregistrer ce droit (contrainte ou erreur base)."}},
                status_code=400,
            )
        response = RedirectResponse(url=redirect_url, status_code=302)
        flash_redirect(
            response,
            "Impossible d’enregistrer ce droit.",
            "error",
            settings.vault_portal_internal_token or "dev",
        )
        return response

    _log_grant_mutation(
        db,
        actor=granted_by,
        grant=grant,
        request=request,
        created=True,
    )
    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("grant audit commit failed grant_id=%s", grant.id)

    # Post-grant provisioning hook (spec §5.3) — after the grant commit so a
    # provisioning failure never rolls back the granted right. Explicit result,
    # never silent; user-subject grants toward apps with a provisioning driver.
    provisioning_summary = None
    try:
        from app.rbac.account_service import provision_for_grant

        provisioning_summary = await provision_for_grant(
            db, settings, grant, actor=granted_by, ip_address=_client_ip(request)
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
