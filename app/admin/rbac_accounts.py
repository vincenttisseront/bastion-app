"""Admin routes — bastion account creation (Keycloak push) + provisioning status.

Router MUST be included BEFORE admin_rbac_access_router in app/main.py:
rbac_access declares ``/admin/rbac/users/{keycloak_user_id}`` which would
otherwise capture ``/admin/rbac/users/new`` (route order matters in FastAPI).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session, joinedload

from app.admin.rbac_access import build_vault_apps_for_user
from app.bastion.bastion_fields import (
    PROVISIONING_DRIVER_LABELS,
    normalize_provisioning_driver,
)
from app.database import get_db
from app.models import App, BastionAccount, BastionAccountProvisioning, RBACGroup, RealmConfig
from app.rbac.account_service import (
    AccountCreationError,
    create_bastion_account,
    delete_bastion_account,
    provision_account_app,
    realm_provisioning_ready,
    retry_bastion_account_keycloak,
    update_bastion_account_identity,
)
from app.rbac.grants_service import (
    ACCESS_LEVELS,
    SYSTEM_ROLES,
    compute_effective_grants,
    list_grants,
    serialize_grant,
)
from app.rbac.keycloak_admin import fetch_keycloak_user, fetch_user_groups
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context, flash_redirect
from app.web.templates import render
from app.web.user_context import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-rbac-accounts"], dependencies=[Depends(require_admin)])


def _ctx(request: Request, settings: Settings, **extra):
    return base_template_context(request, settings, APP_VERSION, **extra)


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP", request.client.host if request.client else "")


def _wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "application/json" in accept or request.headers.get("x-requested-with") == "XMLHttpRequest"


def _provisioning_realms(db: Session) -> list[RealmConfig]:
    realms = db.query(RealmConfig).filter_by(enabled=True).order_by(RealmConfig.slug).all()
    return [r for r in realms if realm_provisioning_ready(r)]


def _form_context(db: Session) -> dict:
    realms = _provisioning_realms(db)
    groups = (
        db.query(RBACGroup)
        .filter(RBACGroup.realm_id.is_not(None), RBACGroup.keycloak_group_id.is_not(None))
        .order_by(RBACGroup.name)
        .all()
    )
    apps = db.query(App).filter_by(enabled=True).order_by(App.label).all()
    return {
        "provision_realms": realms,
        "provision_groups": groups,
        "provision_apps": apps,
        "provisioning_driver_labels": PROVISIONING_DRIVER_LABELS,
    }


def _parse_int_list(values: list[str]) -> list[int]:
    out: list[int] = []
    for raw in values:
        raw = (raw or "").strip()
        if not raw:
            continue
        try:
            out.append(int(raw))
        except ValueError:
            continue
    return out


@router.get("/admin/rbac/users/new")
def admin_rbac_users_new_form(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    ctx = _form_context(db)
    return render(
        "admin/rbac/user_new.html",
        **_ctx(
            request,
            settings,
            form_values={},
            form_error=None,
            active_tab="users",
            **ctx,
        ),
    )


@router.get("/admin/rbac/users/view")
async def admin_rbac_user_view(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
    account_id: int | None = None,
    realm_id: int | None = None,
    keycloak_user_id: str | None = None,
):
    """Dedicated user fiche — identity / groups / grants / vault / provisioning.

    No parent RBAC tabs (Groupes / Matrice / Gouvernance).
    """
    account: BastionAccount | None = None
    if account_id is not None:
        account = (
            db.query(BastionAccount)
            .options(
                joinedload(BastionAccount.realm),
                joinedload(BastionAccount.provisionings).joinedload(
                    BastionAccountProvisioning.application
                ),
            )
            .filter_by(id=account_id)
            .first()
        )
        if account is None:
            raise HTTPException(status_code=404, detail="Compte introuvable")
        realm_id = account.realm_id
        if account.keycloak_user_id:
            keycloak_user_id = account.keycloak_user_id

    if realm_id is None:
        raise HTTPException(status_code=400, detail="realm_id ou account_id requis")

    realm = db.query(RealmConfig).filter_by(id=realm_id).first()
    if realm is None:
        raise HTTPException(status_code=404, detail="Realm introuvable")

    if account is None and keycloak_user_id:
        account = (
            db.query(BastionAccount)
            .options(
                joinedload(BastionAccount.realm),
                joinedload(BastionAccount.provisionings).joinedload(
                    BastionAccountProvisioning.application
                ),
            )
            .filter_by(keycloak_user_id=keycloak_user_id)
            .first()
        )

    if not keycloak_user_id and account is None:
        raise HTTPException(
            status_code=400,
            detail="keycloak_user_id ou account_id requis",
        )

    kc_user = None
    kc_groups: list[dict] = []
    kc_email_diag: dict | None = None
    user_error: str | None = None
    direct_grants: list = []
    effective_grants: list[dict] = []

    if keycloak_user_id:
        try:
            kc_user = await fetch_keycloak_user(realm, keycloak_user_id, settings)
            if kc_user:
                from app.rbac.oidc_email import keycloak_email_diagnostics

                kc_email_diag = keycloak_email_diagnostics(kc_user)
                kc_groups = await fetch_user_groups(realm, keycloak_user_id, settings)
                direct_grants = list_grants(db, keycloak_user_id=keycloak_user_id)
                effective_grants = await compute_effective_grants(
                    db, realm, keycloak_user_id, settings
                )
            else:
                user_error = "Utilisateur Keycloak introuvable"
        except ValueError as exc:
            user_error = str(exc)
        except Exception:
            logger.exception("Failed to load user fiche")
            user_error = "Erreur serveur lors du chargement de l'utilisateur"

    apps = db.query(App).filter_by(enabled=True).order_by(App.label).all()
    provisionings = []
    pending_apps: list[App] = []
    if account is not None:
        provisionings = sorted(
            account.provisionings or [],
            key=lambda r: (r.application.label if r.application else ""),
        )
        done_ids = {r.application_id for r in provisionings}
        pending_ids = account.pending_application_ids or []
        if isinstance(pending_ids, list):
            apps_by_id = {a.id: a for a in apps}
            for raw_id in pending_ids:
                try:
                    aid = int(raw_id)
                except (TypeError, ValueError):
                    continue
                if aid not in done_ids and aid in apps_by_id:
                    pending_apps.append(apps_by_id[aid])

    extra_vault_slugs = {
        r.application.slug
        for r in provisionings
        if r.application and r.status == "success"
    }
    grant_rows = list(effective_grants) + [serialize_grant(g, db) for g in direct_grants]
    vault_apps = build_vault_apps_for_user(
        db,
        keycloak_user_id=keycloak_user_id,
        apps=apps,
        grant_rows=grant_rows if keycloak_user_id else None,
        extra_app_slugs=extra_vault_slugs or None,
    )

    display_name = (
        (kc_user or {}).get("username")
        or (account.username if account else None)
        or keycloak_user_id
        or f"compte #{account.id if account else '?'}"
    )
    view_url = "/admin/rbac/users/view?"
    if account is not None:
        view_url += f"account_id={account.id}"
    else:
        view_url += f"realm_id={realm.id}&keycloak_user_id={keycloak_user_id}"

    from app.files.service import file_grant_select_options, folder_grant_select_options

    return render(
        "admin/rbac/user_view.html",
        **_ctx(
            request,
            settings,
            realm=realm,
            selected_realm=realm,
            account=account,
            keycloak_user_id=keycloak_user_id,
            kc_user=kc_user,
            kc_email_diag=kc_email_diag,
            kc_groups=kc_groups,
            user_error=user_error,
            direct_grants=[serialize_grant(g, db) for g in direct_grants],
            effective_grants=effective_grants,
            vault_apps=vault_apps,
            provisionings=provisionings,
            pending_apps=pending_apps,
            apps=apps,
            file_options=file_grant_select_options(db),
            folder_options=folder_grant_select_options(db),
            system_roles=SYSTEM_ROLES,
            access_levels=sorted(ACCESS_LEVELS),
            display_name=display_name,
            view_url=view_url,
            provisioning_driver_labels=PROVISIONING_DRIVER_LABELS,
        ),
    )


@router.post("/admin/rbac/users/new")
async def admin_rbac_users_new_submit(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    form = await request.form()
    realm_id_raw = (str(form.get("realm_id") or "")).strip()
    username = str(form.get("username") or "")
    email = str(form.get("email") or "")
    first_name = str(form.get("first_name") or "")
    last_name = str(form.get("last_name") or "")
    organization = str(form.get("organization") or "")
    group_ids = _parse_int_list([str(v) for v in form.getlist("group_ids")])
    application_ids = _parse_int_list([str(v) for v in form.getlist("application_ids")])

    form_values = {
        "realm_id": realm_id_raw,
        "username": username,
        "email": email,
        "first_name": first_name,
        "last_name": last_name,
        "organization": organization,
        "group_ids": group_ids,
        "application_ids": application_ids,
    }

    def _form_error(message: str, status_code: int = 400):
        if _wants_json(request):
            return JSONResponse(
                {"ok": False, "errors": {"_form": message}}, status_code=status_code
            )
        return render(
            "admin/rbac/user_new.html",
            **_ctx(
                request,
                settings,
                form_values=form_values,
                form_error=message,
                active_tab="users",
                **_form_context(db),
            ),
            status_code=status_code,
        )

    try:
        realm_id = int(realm_id_raw)
    except ValueError:
        return _form_error("Realm cible requis")
    realm = db.query(RealmConfig).filter_by(id=realm_id).first()
    if realm is None:
        return _form_error("Realm introuvable", status_code=404)
    if not realm_provisioning_ready(realm):
        return _form_error(
            "Provisioning non activé pour ce realm — activez-le dans la fiche realm "
            "(compte de service provisioning + opt-in explicite)."
        )

    # Groups belong to a realm — drop any id that is not for the selected realm
    # (UI filters them, but never trust a crafted POST).
    if group_ids:
        allowed = {
            g.id
            for g in db.query(RBACGroup)
            .filter(RBACGroup.id.in_(group_ids), RBACGroup.realm_id == realm.id)
            .all()
        }
        group_ids = [gid for gid in group_ids if gid in allowed]
        form_values["group_ids"] = group_ids

    try:
        account, step_errors = await create_bastion_account(
            db,
            settings,
            realm=realm,
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            organization=organization,
            group_ids=group_ids,
            application_ids=application_ids,
            actor=user.email,
            ip_address=_client_ip(request),
        )
    except AccountCreationError as exc:
        return _form_error(str(exc))

    if _wants_json(request):
        return JSONResponse(
            {
                "ok": account.status != "pending",
                "account_id": account.id,
                "status": account.status,
                "keycloak_user_id": account.keycloak_user_id,
                "errors": step_errors,
            },
            status_code=200 if account.status != "pending" else 502,
        )

    response = RedirectResponse(url=f"/admin/rbac/accounts/{account.id}", status_code=302)
    secret = settings.vault_portal_internal_token or "dev"
    if account.status == "pending":
        flash_redirect(
            response,
            f"Échec création Keycloak : {account.last_error}",
            "error",
            secret,
        )
    elif step_errors:
        flash_redirect(
            response,
            "Compte Keycloak créé, mais certaines étapes ont échoué : "
            + " ; ".join(step_errors),
            "warning",
            secret,
        )
    else:
        flash_redirect(response, "Compte créé.", "success", secret)
    return response


def _account_or_404(db: Session, account_id: int) -> BastionAccount:
    account = db.query(BastionAccount).filter_by(id=account_id).first()
    if account is None:
        raise HTTPException(status_code=404, detail="Compte bastion introuvable")
    return account


def _crushftp_group_names_for_account(db: Session, account: BastionAccount) -> list[str]:
    """RBAC group names stored at creation — used by CrushFTP membership join."""
    raw = account.pending_group_ids or []
    if not isinstance(raw, list) or not raw:
        return []
    ids: list[int] = []
    for item in raw:
        try:
            ids.append(int(item))
        except (TypeError, ValueError):
            continue
    if not ids:
        return []
    groups = db.query(RBACGroup).filter(RBACGroup.id.in_(ids)).all()
    return [g.name for g in groups if g.name]


def _safe_redirect_url(raw: str | None, fallback: str) -> str:
    """Only allow same-origin relative admin paths (open-redirect guard)."""
    value = (raw or "").strip()
    if value.startswith("/admin/") and "://" not in value and "\\" not in value:
        return value
    return fallback


@router.get("/admin/rbac/accounts/{account_id}")
def admin_rbac_account_detail(
    account_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    account = _account_or_404(db, account_id)
    realm = account.realm
    provisionings = sorted(
        account.provisionings or [], key=lambda r: (r.application.label if r.application else "")
    )
    done_ids = {r.application_id for r in provisionings}
    pending_apps: list[App] = []
    pending_ids = account.pending_application_ids or []
    if isinstance(pending_ids, list) and pending_ids:
        parsed_ids: list[int] = []
        for raw_id in pending_ids:
            try:
                parsed_ids.append(int(raw_id))
            except (TypeError, ValueError):
                continue
        if parsed_ids:
            apps_by_id = {
                a.id: a for a in db.query(App).filter(App.id.in_(parsed_ids)).all()
            }
            for aid in parsed_ids:
                if aid not in done_ids and aid in apps_by_id:
                    pending_apps.append(apps_by_id[aid])

    keycloak_console_url = None
    if account.keycloak_user_id and realm and "/realms/" in (realm.issuer_url or ""):
        base = realm.issuer_url.split("/realms/")[0].rstrip("/")
        realm_name = realm.issuer_url.rstrip("/").split("/realms/")[-1]
        keycloak_console_url = (
            f"{base}/admin/master/console/#/{realm_name}/users/{account.keycloak_user_id}/settings"
        )

    if _wants_json(request):
        return JSONResponse(
            {
                "ok": True,
                "account": {
                    "id": account.id,
                    "realm_slug": realm.slug if realm else None,
                    "username": account.username,
                    "email": account.email,
                    "status": account.status,
                    "origin": account.origin,
                    "keycloak_user_id": account.keycloak_user_id,
                    "last_error": account.last_error,
                },
                "provisionings": [
                    {
                        "application_id": row.application_id,
                        "app_slug": row.application.slug if row.application else None,
                        "driver": row.driver_name,
                        "status": row.status,
                        "detail": row.detail,
                    }
                    for row in provisionings
                ],
                "pending_application_ids": [
                    a.id for a in pending_apps
                ],
            }
        )

    provision_apps = db.query(App).filter_by(enabled=True).order_by(App.label).all()
    provisioned_by_app = {r.application_id: r for r in provisionings}
    pending_ids_set = {a.id for a in pending_apps}
    extra_vault_slugs = {
        r.application.slug
        for r in provisionings
        if r.application and r.status == "success"
    }
    vault_apps = build_vault_apps_for_user(
        db,
        keycloak_user_id=account.keycloak_user_id,
        apps=provision_apps,
        grant_rows=None,
        extra_app_slugs=extra_vault_slugs or None,
    )

    return render(
        "admin/rbac/account_detail.html",
        **_ctx(
            request,
            settings,
            account=account,
            realm=realm,
            provisionings=provisionings,
            pending_apps=pending_apps,
            provision_apps=provision_apps,
            provisioned_by_app=provisioned_by_app,
            pending_ids_set=pending_ids_set,
            provisioning_driver_labels=PROVISIONING_DRIVER_LABELS,
            keycloak_console_url=keycloak_console_url,
            vault_apps=vault_apps,
            active_tab="users",
        ),
    )


@router.post("/admin/rbac/accounts/{account_id}/identity")
async def admin_rbac_account_update_identity(
    account_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    email: str = Form(""),
    first_name: str = Form(""),
    last_name: str = Form(""),
    organization: str = Form(""),
    redirect_url: str = Form(""),
):
    """Edit identity — BastionAccount + Keycloak + re-push vault credentials to apps."""
    account = _account_or_404(db, account_id)
    secret = settings.vault_portal_internal_token or "dev"
    fallback = f"/admin/rbac/users/view?account_id={account.id}#identite"
    try:
        step_errors = await update_bastion_account_identity(
            db,
            settings,
            account=account,
            email=email,
            first_name=first_name,
            last_name=last_name,
            organization=organization,
            actor=user.email,
            ip_address=_client_ip(request),
        )
    except AccountCreationError as exc:
        if _wants_json(request):
            return JSONResponse({"ok": False, "errors": {"_form": str(exc)}}, status_code=400)
        response = RedirectResponse(
            url=_safe_redirect_url(redirect_url, fallback), status_code=302
        )
        flash_redirect(response, str(exc), "error", secret)
        return response

    if _wants_json(request):
        return JSONResponse(
            {
                "ok": len(step_errors) == 0,
                "errors": step_errors,
                "account_id": account.id,
            }
        )
    response = RedirectResponse(
        url=_safe_redirect_url(redirect_url, fallback), status_code=302
    )
    if step_errors:
        flash_redirect(
            response,
            "Identité enregistrée avec avertissements : " + " · ".join(step_errors),
            "warn",
            secret,
        )
    else:
        flash_redirect(
            response,
            "Identité mise à jour (bastion + Keycloak + apps provisionnées).",
            "success",
            secret,
        )
    return response


@router.post("/admin/rbac/accounts/{account_id}/retry-keycloak")
async def admin_rbac_account_retry_keycloak(
    account_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Bouton « Relancer Keycloak » — retry explicite de l'étape IdP (+ groupes/apps en attente)."""
    account = _account_or_404(db, account_id)
    secret = settings.vault_portal_internal_token or "dev"
    try:
        step_errors = await retry_bastion_account_keycloak(
            db,
            settings,
            account=account,
            actor=user.email,
            ip_address=_client_ip(request),
        )
    except AccountCreationError as exc:
        if _wants_json(request):
            return JSONResponse(
                {"ok": False, "errors": {"_form": str(exc)}}, status_code=400
            )
        response = RedirectResponse(
            url=f"/admin/rbac/accounts/{account.id}", status_code=302
        )
        flash_redirect(response, str(exc), "error", secret)
        return response

    if _wants_json(request):
        return JSONResponse(
            {
                "ok": account.status != "pending",
                "account_id": account.id,
                "status": account.status,
                "keycloak_user_id": account.keycloak_user_id,
                "errors": step_errors,
            },
            status_code=200 if account.status != "pending" else 502,
        )

    response = RedirectResponse(url=f"/admin/rbac/accounts/{account.id}", status_code=302)
    if account.status == "pending":
        flash_redirect(
            response,
            f"Relance Keycloak échouée : {account.last_error}",
            "error",
            secret,
        )
    elif step_errors:
        flash_redirect(
            response,
            "Keycloak OK, mais certaines étapes ont échoué : " + " ; ".join(step_errors),
            "warning",
            secret,
        )
    else:
        flash_redirect(response, "Relance Keycloak réussie.", "success", secret)
    return response


@router.post("/admin/rbac/accounts/{account_id}/provision")
async def admin_rbac_account_provision_selected(
    account_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Lancer le provisioning pour les applications cochées sur la fiche compte."""
    account = _account_or_404(db, account_id)
    secret = settings.vault_portal_internal_token or "dev"
    dest = f"/admin/rbac/accounts/{account.id}"

    if not account.keycloak_user_id:
        response = RedirectResponse(url=dest, status_code=302)
        flash_redirect(
            response,
            "Compte Keycloak non créé — relancez d'abord l'étape Keycloak.",
            "error",
            secret,
        )
        return response

    form = await request.form()
    application_ids = _parse_int_list([str(v) for v in form.getlist("application_ids")])
    if not application_ids:
        response = RedirectResponse(url=dest, status_code=302)
        flash_redirect(response, "Sélectionnez au moins une application.", "warning", secret)
        return response

    crush_groups = _crushftp_group_names_for_account(db, account)
    results: list[str] = []
    failures = 0
    for application_id in application_ids:
        app = db.query(App).filter_by(id=application_id, enabled=True).first()
        if app is None:
            results.append(f"#{application_id} introuvable")
            failures += 1
            continue
        group_names = (
            crush_groups
            if normalize_provisioning_driver(app.provisioning_driver) == "crushftp"
            else None
        )
        row = await provision_account_app(
            db,
            settings,
            account=account,
            app=app,
            actor=user.email,
            ip_address=_client_ip(request),
            group_names=group_names or None,
        )
        if row.status == "failed":
            failures += 1
            results.append(f"{app.label} : {row.detail}")
        else:
            results.append(f"{app.label} : {row.status}")

    if _wants_json(request):
        return JSONResponse(
            {
                "ok": failures == 0,
                "retried": len(application_ids),
                "failures": failures,
                "results": results,
                "account_status": account.status,
            },
            status_code=200 if failures == 0 else 502,
        )

    response = RedirectResponse(url=dest, status_code=302)
    if failures:
        flash_redirect(
            response,
            f"Provisioning partiel ({failures} échec) : " + " ; ".join(results),
            "warning",
            secret,
        )
    else:
        flash_redirect(
            response,
            "Provisioning lancé : " + " ; ".join(results),
            "success",
            secret,
        )
    return response


@router.post("/admin/rbac/accounts/{account_id}/provision/{application_id}")
async def admin_rbac_account_provision_retry(
    account_id: int,
    application_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    redirect_url: str | None = Form(None),
):
    """Bouton « Relancer » — retry explicite, jamais de retry automatique silencieux."""
    account = _account_or_404(db, account_id)
    app = db.query(App).filter_by(id=application_id).first()
    if app is None:
        raise HTTPException(status_code=404, detail="Application introuvable")

    group_names = None
    if normalize_provisioning_driver(app.provisioning_driver) == "crushftp":
        group_names = _crushftp_group_names_for_account(db, account) or None

    row = await provision_account_app(
        db,
        settings,
        account=account,
        app=app,
        actor=user.email,
        ip_address=_client_ip(request),
        group_names=group_names,
    )

    if _wants_json(request):
        return JSONResponse(
            {
                "ok": row.status in ("success", "not_applicable"),
                "status": row.status,
                "detail": row.detail,
                "account_status": account.status,
            }
        )

    dest = _safe_redirect_url(redirect_url, f"/admin/rbac/accounts/{account.id}")
    response = RedirectResponse(url=dest, status_code=302)
    secret = settings.vault_portal_internal_token or "dev"
    if row.status == "success":
        flash_redirect(response, f"Provisioning {app.label} : succès.", "success", secret)
    elif row.status == "not_applicable":
        flash_redirect(response, f"Provisioning {app.label} : non applicable.", "info", secret)
    else:
        flash_redirect(
            response, f"Provisioning {app.label} : échec — {row.detail}", "error", secret
        )
    return response


@router.post("/admin/rbac/accounts/{account_id}/delete")
async def admin_rbac_account_delete(
    account_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    confirm_username: str = Form(""),
    force: str = Form(""),
):
    """Suppression complète — apps provisionnées + Keycloak + vault/grants + fiche.

    Confirmation explicite : l'identifiant exact doit être resaisi. Sans
    ``force``, la fiche bastion est conservée si une étape distante échoue
    (retry possible) — jamais de suppression silencieusement partielle.
    """
    account = _account_or_404(db, account_id)
    secret = settings.vault_portal_internal_token or "dev"
    detail_url = f"/admin/rbac/accounts/{account.id}"

    if (confirm_username or "").strip() != account.username:
        message = (
            "Confirmation invalide — saisissez exactement l'identifiant "
            f"« {account.username} » pour supprimer le compte."
        )
        if _wants_json(request):
            return JSONResponse(
                {"ok": False, "errors": {"confirm_username": message}}, status_code=400
            )
        response = RedirectResponse(url=detail_url, status_code=302)
        flash_redirect(response, message, "error", secret)
        return response

    username = account.username
    deleted, errors = await delete_bastion_account(
        db,
        settings,
        account=account,
        actor=user.email,
        ip_address=_client_ip(request),
        force=force.strip().lower() in ("1", "true", "on", "yes"),
    )

    if _wants_json(request):
        return JSONResponse(
            {"ok": deleted, "deleted": deleted, "errors": errors},
            status_code=200 if deleted else 502,
        )

    if not deleted:
        response = RedirectResponse(url=detail_url, status_code=302)
        flash_redirect(
            response,
            "Suppression incomplète — fiche conservée : " + " ; ".join(errors),
            "error",
            secret,
        )
        return response

    response = RedirectResponse(url="/admin/rbac/users", status_code=302)
    if errors:
        flash_redirect(
            response,
            f"Compte « {username} » supprimé (forcé) malgré des erreurs : "
            + " ; ".join(errors),
            "warning",
            secret,
        )
    else:
        flash_redirect(
            response,
            f"Compte « {username} » supprimé partout (applications, Keycloak, "
            "vault, droits, fiche bastion).",
            "success",
            secret,
        )
    return response


@router.post("/admin/rbac/accounts/{account_id}/provision-retry-all")
async def admin_rbac_account_provision_retry_all(
    account_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    redirect_url: str | None = Form(None),
):
    """Relance toutes les apps en échec + celles encore dans pending_application_ids."""
    account = _account_or_404(db, account_id)
    if not account.keycloak_user_id:
        raise HTTPException(
            status_code=400,
            detail="Compte Keycloak non créé — relancez d'abord l'étape Keycloak.",
        )

    app_ids: set[int] = set()
    for row in account.provisionings or []:
        if row.status == "failed":
            app_ids.add(row.application_id)
    pending_ids = account.pending_application_ids or []
    if isinstance(pending_ids, list):
        for raw in pending_ids:
            try:
                app_ids.add(int(raw))
            except (TypeError, ValueError):
                continue

    crush_groups = _crushftp_group_names_for_account(db, account)
    results: list[str] = []
    failures = 0
    for application_id in sorted(app_ids):
        app = db.query(App).filter_by(id=application_id).first()
        if app is None:
            results.append(f"#{application_id} introuvable")
            failures += 1
            continue
        group_names = (
            crush_groups
            if normalize_provisioning_driver(app.provisioning_driver) == "crushftp"
            else None
        )
        row = await provision_account_app(
            db,
            settings,
            account=account,
            app=app,
            actor=user.email,
            ip_address=_client_ip(request),
            group_names=group_names or None,
        )
        if row.status == "failed":
            failures += 1
            results.append(f"{app.label} : {row.detail}")
        else:
            results.append(f"{app.label} : {row.status}")

    if _wants_json(request):
        return JSONResponse(
            {
                "ok": failures == 0,
                "retried": len(app_ids),
                "failures": failures,
                "results": results,
                "account_status": account.status,
            },
            status_code=200 if failures == 0 else 502,
        )

    dest = _safe_redirect_url(redirect_url, f"/admin/rbac/accounts/{account.id}")
    response = RedirectResponse(url=dest, status_code=302)
    secret = settings.vault_portal_internal_token or "dev"
    if not app_ids:
        flash_redirect(response, "Rien à relancer.", "info", secret)
    elif failures:
        flash_redirect(
            response,
            f"Relance partielle ({failures} échec) : " + " ; ".join(results),
            "warning",
            secret,
        )
    else:
        flash_redirect(response, "Provisioning relancé avec succès.", "success", secret)
    return response
