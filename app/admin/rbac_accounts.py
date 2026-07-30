"""Admin routes — bastion account creation (Keycloak push) + provisioning status.

Router MUST be included BEFORE admin_rbac_access_router in app/main.py:
rbac_access declares ``/admin/rbac/users/{keycloak_user_id}`` which would
otherwise capture ``/admin/rbac/users/new`` (route order matters in FastAPI).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.bastion.bastion_fields import PROVISIONING_DRIVER_LABELS
from app.database import get_db
from app.models import App, BastionAccount, RBACGroup, RealmConfig
from app.rbac.account_service import (
    AccountCreationError,
    create_bastion_account,
    provision_account_app,
    realm_provisioning_ready,
    retry_bastion_account_keycloak,
)
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
    group_ids = _parse_int_list([str(v) for v in form.getlist("group_ids")])
    application_ids = _parse_int_list([str(v) for v in form.getlist("application_ids")])

    form_values = {
        "realm_id": realm_id_raw,
        "username": username,
        "email": email,
        "first_name": first_name,
        "last_name": last_name,
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

    return render(
        "admin/rbac/account_detail.html",
        **_ctx(
            request,
            settings,
            account=account,
            realm=realm,
            provisionings=provisionings,
            pending_apps=pending_apps,
            keycloak_console_url=keycloak_console_url,
            active_tab="users",
        ),
    )


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

    row = await provision_account_app(
        db,
        settings,
        account=account,
        app=app,
        actor=user.email,
        ip_address=_client_ip(request),
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

    results: list[str] = []
    failures = 0
    for application_id in sorted(app_ids):
        app = db.query(App).filter_by(id=application_id).first()
        if app is None:
            results.append(f"#{application_id} introuvable")
            failures += 1
            continue
        row = await provision_account_app(
            db,
            settings,
            account=account,
            app=app,
            actor=user.email,
            ip_address=_client_ip(request),
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
