"""HTML page routes for Bastion Pro portal."""

import hmac
import logging

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.access_modes import (
    is_user_catalogue_mode,
    normalize_access_mode,
    validate_app_access_fields,
)
from app.bastion.bastion_fields import (
    PROVISIONING_DRIVER_LABELS,
    normalize_auth_mode,
    normalize_credential_mode,
    normalize_identity_format,
    normalize_provisioning_driver,
    resolve_robotic_driver,
    validate_generic_form_fields,
    vault_enabled_for_app,
)
from app.robotic.robotic_session_cookies import normalize_injected_cookie_scope
from app.admin.export import export_app_catalogue_files
from app.admin.infra_host_apply import request_host_apply, wait_for_host_apply
from app.audit import list_audit_entries, log_action
from app.health_probe import compute_health_score, compute_status_counts, probe_row_from_app
from app.auth_flow import get_default_idp_realm, oauth2_start_url, resolve_rd, setup_url
from app.breakglass import (
    COOKIE_NAME,
    clear_breakglass_cookie,
    issue_breakglass_token,
    process_breakglass_auth_request,
    resolve_breakglass_signing_secret,
    revoke_breakglass_session_from_request,
    set_breakglass_cookie,
)
from app.breakglass_store import (
    create_initial_breakglass_account,
    has_active_breakglass_account,
    verify_breakglass_password,
)
from app.database import get_db
from app.models import AccessGrant, App, PendingHost, PendingUser, RBACGroup, RealmConfig
from app.bastion.pending_host_service import (
    approve_pending_host,
    reject_pending_host,
    suggest_slug,
)
from app.rbac.grants_service import count_grants_by_application
from app.robotic.robotic_session_cookies import shared_parent_domain
from app.sso_settings import Settings, get_settings
from app.web.app_logos import (
    LogoValidationError,
    clear_app_logo,
    logo_public_url,
    save_app_logo,
)
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context, flash_redirect
from app.web.metrics_service import get_dashboard_metrics
from app.request_client_ip import client_ip_from_request
from app.web.sessions_service import (
    build_session_groups,
    get_active_sessions,
    touch_portal_session,
)
from app.web.templates import render
from app.vault.app_credential_service import (
    EncryptionNotConfiguredError,
    VaultError,
    get_app_credential,
    set_app_credential,
)
from app.vault.credential_connection_test import (
    credential_test_legacy_response,
    test_app_credential_connection,
)
from app.vault.user_app_credential_service import (
    delete_user_credential,
    get_user_credential,
    has_user_override,
    set_user_credential,
)
from app.secret_crypto import encrypt_secret
from app.testing_framework.throttle import throttle_retry_after
from app.web.user_context import get_user_context, is_portal_admin, require_admin, require_user
from pydantic import BaseModel, Field

router = APIRouter(tags=["pages"])
# Authenticated (non-admin) pages — new routes inherit require_user.
authenticated_router = APIRouter(
    tags=["pages-user"],
    dependencies=[Depends(require_user)],
)
# Admin pages — new routes inherit require_admin.
admin_router = APIRouter(
    tags=["pages-admin"],
    dependencies=[Depends(require_admin)],
)

logger = logging.getLogger(__name__)

_DESC_MAX = 140


def _warn_if_fqdn_cookie_domain_incompatible(
    *,
    access_mode: str,
    public_fqdn: str | None,
    portal_domain: str,
    app_slug: str,
) -> None:
    if normalize_access_mode(access_mode) != "subdomain_proxy":
        return
    fqdn = (public_fqdn or "").strip()
    if not fqdn:
        return
    if shared_parent_domain(fqdn, portal_domain or "") is None:
        logger.warning(
            "App %s FQDN %r shares no parent domain with portal %r — "
            "cross-subdomain session cookies will never work for this combination",
            app_slug,
            fqdn,
            portal_domain,
        )


def _normalize_description(raw: str | None) -> str | None:
    text = (raw or "").strip()
    if not text:
        return None
    if len(text) > _DESC_MAX:
        text = text[:_DESC_MAX]
    return text


def _auth_form_values(
    auth_mode: str = "sso",
    login_form_url: str = "",
    login_username_field: str = "username",
    login_password_field: str = "password",
    login_http_method: str = "POST",
    login_extra_fields: str = "",
) -> dict:
    return {
        "auth_mode": normalize_auth_mode(auth_mode),
        "login_form_url": login_form_url,
        "login_username_field": login_username_field or "username",
        "login_password_field": login_password_field or "password",
        "login_http_method": (login_http_method or "POST").upper(),
        "login_extra_fields": login_extra_fields,
    }


def _apply_auth_config(
    app: App,
    *,
    auth_mode: str,
    login_form_url: str,
    login_username_field: str,
    login_password_field: str,
    login_http_method: str,
    login_extra_fields: str,
    credential_mode: str = "shared",
    identity_format: str = "email",
    injected_cookie_scope: str = "host_only",
) -> None:
    mode = normalize_auth_mode(auth_mode)
    app.auth_mode = mode
    app.robotic_driver = resolve_robotic_driver(mode, app.robotic_driver)
    app.login_form_url = (login_form_url or "").strip() or None
    app.login_username_field = (login_username_field or "username").strip() or "username"
    app.login_password_field = (login_password_field or "password").strip() or "password"
    app.login_http_method = (login_http_method or "POST").strip().upper()
    app.login_extra_fields = (login_extra_fields or "").strip() or None
    app.credential_mode = normalize_credential_mode(credential_mode)
    app.identity_format = normalize_identity_format(identity_format)
    app.injected_cookie_scope = normalize_injected_cookie_scope(injected_cookie_scope)


def _apply_crushftp_admin_config(
    app: App,
    settings: Settings,
    *,
    crushftp_admin_base_url: str,
    crushftp_admin_server_group: str,
    crushftp_admin_username: str,
    crushftp_admin_password: str,
    crushftp_vfs_base_path: str = "",
) -> dict[str, str]:
    """Persist CrushFTP Admin API fields. Blank password keeps existing ciphertext."""
    errors: dict[str, str] = {}
    app.crushftp_admin_base_url = (crushftp_admin_base_url or "").strip() or None
    group = (crushftp_admin_server_group or "").strip()
    app.crushftp_admin_server_group = group or None
    app.crushftp_admin_username = (crushftp_admin_username or "").strip() or None
    raw_vfs = (crushftp_vfs_base_path or "").strip().replace("\\", "/")
    app.crushftp_vfs_base_path = raw_vfs.rstrip("/") or None
    plain = (crushftp_admin_password or "").strip()
    if plain:
        try:
            app.crushftp_admin_password_encrypted = encrypt_secret(plain, settings)
        except ValueError as exc:
            errors["crushftp_admin_password"] = (
                str(exc) or "Chiffrement du mot de passe impossible"
            )
    return errors


def _validate_auth_fields(
    access_mode: str,
    auth_mode: str,
    login_form_url: str,
    login_username_field: str,
    login_password_field: str,
    login_http_method: str,
    login_extra_fields: str,
) -> dict[str, str]:
    errors: dict[str, str] = {}
    mode = normalize_access_mode(access_mode)
    auth = normalize_auth_mode(auth_mode)
    if mode in ("sso_gate", "public_proxy") and auth != "sso":
        errors["auth_mode"] = (
            "Le vault robotic n'est pas disponible pour ce mode d'accès."
        )
    if auth == "generic_form":
        errors.update(
            validate_generic_form_fields(
                login_form_url,
                login_username_field,
                login_password_field,
                login_http_method,
                login_extra_fields,
            )
        )
    return errors


def _ctx(request: Request, settings: Settings, **extra):
    return base_template_context(request, settings, APP_VERSION, **extra)


def _client_ip(request: Request) -> str:
    return client_ip_from_request(request)


def _show_breakglass_form(request: Request, db: Session, settings: Settings) -> bool:
    """True only for LAN / allowlisted clients — never expose BG UI on the public Internet."""
    from app.security.banning.engine import is_breakglass_ip_allowed

    return is_breakglass_ip_allowed(
        db, _client_ip(request), rfc1918_cidrs=settings.rfc1918_cidrs
    )


def _login_audience_label(realm: RealmConfig) -> str:
    """Short audience label for the login chooser (Interne / Clients / name)."""
    custom = (getattr(realm, "login_label", None) or "").strip()
    if custom:
        return custom
    blob = f"{realm.slug or ''} {realm.name or ''}".lower()
    if any(token in blob for token in ("client", "externe", "customer")):
        return "Clients"
    if any(
        token in blob
        for token in ("interne", "internal", "staff", "ar-system", "arsystem")
    ):
        return "Interne"
    return (realm.name or realm.slug or "Realm").strip()


def _realm_is_login_ready(realm: RealmConfig) -> bool:
    """Enabled realm with enough OIDC config to offer a login path."""
    return bool(
        realm.enabled
        and getattr(realm, "show_on_login", True)
        and (realm.issuer_url or "").strip()
        and (realm.client_id or "").strip()
    )


def _login_surface_flags(
    request: Request,
    db: Session,
    settings: Settings,
    *,
    rd: str,
    preferred_realm: str | None = None,
) -> dict:
    """Shared flags for auth/login.html (native SSO vs oauth2-proxy vs break-glass)."""
    from app.oidc_native_session import is_oidc_native_session_enabled_for_realm

    default = get_default_idp_realm(db)
    enabled_rows = (
        db.query(RealmConfig)
        .filter(RealmConfig.enabled.is_(True))
        .order_by(RealmConfig.slug.asc())
        .all()
    )
    # Default first, then other enabled realms (stable chooser order).
    ordered: list[RealmConfig] = []
    if default is not None:
        ordered.append(default)
    for row in enabled_rows:
        if default is None or row.id != default.id:
            ordered.append(row)

    # Chooser lists every login-ready realm (native form and/or oauth2-proxy).
    login_realms: list[RealmConfig] = [
        row for row in ordered if _realm_is_login_ready(row)
    ]

    want = (preferred_realm or request.query_params.get("realm") or "").strip().lower()
    selected: RealmConfig | None = None
    if want:
        for row in login_realms:
            if (row.slug or "").lower() == want:
                selected = row
                break
    if selected is None and login_realms:
        selected = login_realms[0]

    selected_native = bool(
        selected
        and is_oidc_native_session_enabled_for_realm(db, selected.slug, settings)
    )
    show_native = selected_native
    # oauth2-proxy CTA for the selected realm when it is not on the native pilot.
    oauth2_url = (
        oauth2_start_url(selected.slug, rd)
        if selected is not None and not selected_native
        else None
    )
    from app.rbac.access_request_service import realms_advertising_access_requests

    access_realms = realms_advertising_access_requests(db)
    native_realm_options = [
        {
            "slug": row.slug,
            "name": row.name,
            "label": _login_audience_label(row),
            "native": is_oidc_native_session_enabled_for_realm(
                db, row.slug, settings
            ),
            "mfa": bool(getattr(row, "oidc_mfa_enabled", True)),
        }
        for row in login_realms
    ]
    return {
        "show_native_login": show_native,
        "native_realm_slug": selected.slug if selected else None,
        "native_realm_name": selected.name if selected else None,
        "native_realm_label": (
            _login_audience_label(selected) if selected else None
        ),
        "native_realm_options": native_realm_options,
        "show_realm_chooser": len(native_realm_options) > 1,
        "oauth2_url": oauth2_url,
        "show_breakglass": _show_breakglass_form(request, db, settings),
        "show_access_request": bool(access_realms),
        "rd": rd,
    }


@router.get("/")
def root():
    return RedirectResponse(url="/apps", status_code=302)


@admin_router.get("/dashboard")
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    touch_portal_session(db, user, _client_ip(request), request=request)
    metrics = get_dashboard_metrics(db)
    recent_audit, _ = list_audit_entries(db, limit=8)
    from app.web.pending_queue_service import build_pending_action_items

    pending_queue = build_pending_action_items(db)
    return render(
        "dashboard/index.html",
        **_ctx(
            request,
            settings,
            metrics=metrics,
            recent_audit=recent_audit,
            pending_queue=pending_queue,
        ),
    )


@authenticated_router.get("/sessions")
def sessions_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_user),
    kind: str | None = Query(None),
):
    if is_portal_admin(user, db, settings):
        user.is_admin = True
    touch_portal_session(db, user, _client_ip(request), request=request)
    filter_kind = kind if kind in ("user", "app") else None
    sessions = get_active_sessions(db, viewer=user, kind=filter_kind)
    return render(
        "sessions/index.html",
        **_ctx(
            request,
            settings,
            sessions=sessions,
            session_groups=build_session_groups(db, sessions),
            session_kind=filter_kind or "all",
            session_counts={
                "all": len(get_active_sessions(db, viewer=user)),
                "user": len(get_active_sessions(db, viewer=user, kind="user")),
                "app": len(get_active_sessions(db, viewer=user, kind="app")),
            },
        ),
    )


@authenticated_router.get("/catalogue")
def catalogue_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_user),
):
    from app.rbac.effective_access_service import get_effective_apps_for_user

    if is_portal_admin(user, db, settings):
        user.is_admin = True
        apps = (
            db.query(App)
            .filter_by(enabled=True)
            .order_by(App.label)
            .all()
        )
        apps = [a for a in apps if is_user_catalogue_mode(a.access_mode)]
    else:
        # Single source of truth: AccessGrant (legacy group↔app links backfilled as launch).
        entries = get_effective_apps_for_user(
            db,
            keycloak_user_id=user.keycloak_user_id,
            group_names=user.groups,
        )
        apps = [e.app for e in entries]
    grant_counts = count_grants_by_application(db) if user.is_admin else {}
    return render(
        "catalogue/index.html",
        **_ctx(request, settings, apps=apps, grant_counts=grant_counts),
    )


# --- Auth ---

_MIN_SETUP_PASSWORD_LEN = 12


def _breakglass_login_response(
    username: str,
    request: Request,
    settings: Settings,
    db: Session,
    rd: str,
) -> RedirectResponse:
    from app.security.banning.engine import record_successful_login

    token, jti = issue_breakglass_token(
        db,
        username,
        resolve_breakglass_signing_secret(settings, db=db),
        request=request,
    )
    db.commit()
    try:
        record_successful_login(
            db, ip=_client_ip(request), username=username
        )
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    response = RedirectResponse(url=rd, status_code=302)
    set_breakglass_cookie(response, token, settings)
    log_action(
        db,
        actor=username,
        action="breakglass.login",
        details={"jti": jti},
        ip_address=_client_ip(request),
    )
    flash_redirect(
        response,
        "Connexion break-glass réussie.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


def _record_sso_failure_from_request(request: Request, db: Session) -> None:
    """Best-effort: IdP failures never hit FastAPI password verify — count return errors."""
    from app.security.banning.engine import evaluate_login_attempt

    err = (request.query_params.get("error") or request.query_params.get("sso_error") or "").strip()
    if not err:
        return
    username = (
        request.query_params.get("username")
        or request.query_params.get("login_hint")
        or ""
    ).strip()
    evaluate_login_attempt(
        db,
        ip=_client_ip(request),
        username=username or "sso",
        success=False,
    )


@router.get("/login")
@router.get("/auth/login")
@router.get("/breakglass")
def login_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    rd = resolve_rd(request, portal_domain=settings.portal_domain or "")
    try:
        _record_sso_failure_from_request(request, db)
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    user = get_user_context(request, settings, db=db)
    if user and user.is_breakglass:
        # Must match /internal/oauth2-auth (binding / jti). Soft cookie checks alone
        # caused login→/apps→401→login loops after IP-chain or revoke changes.
        bg = request.cookies.get(COOKIE_NAME)
        if not bg:
            user = None
        else:
            result = process_breakglass_auth_request(
                db, request, bg, settings, rotate=False
            )
            try:
                db.commit()
            except Exception:
                db.rollback()
            if not result.ok:
                response = render(
                    "auth/login.html",
                    **_ctx(
                        request,
                        settings,
                        hide_chrome=True,
                        login_error="Session break-glass expirée ou invalide — reconnectez-vous.",
                        login_panel="local",
                        **_login_surface_flags(request, db, settings, rd=rd),
                    ),
                )
                clear_breakglass_cookie(response)
                return response
    # Absolute subdomain rd= (from @portal_redirect) must never bounce back unless
    # subdomain-auth would accept this session for that Host — otherwise the
    # transfer↔login loop (HAR: login 302 → transfer auth_request 401 → login).
    from urllib.parse import urlparse

    from app.auth import (
        extract_oidc_session_cookie_raw,
        iter_oidc_session_cookie_candidates,
    )
    from app.oidc_bff import set_oidc_session_cookie, validate_oidc_session_cookie
    from app.oidc_native_session import is_oidc_native_session_enabled_for_realm
    from app.subdomain.subdomain_auth import native_subdomain_auth_would_allow

    raw_session = None
    native_ok = False
    for candidate in iter_oidc_session_cookie_candidates(request, settings):
        claims = validate_oidc_session_cookie(candidate, db=db, settings=settings)
        if claims is None:
            continue
        if not is_oidc_native_session_enabled_for_realm(db, claims.realm, settings):
            continue
        raw_session = candidate
        native_ok = True
        break
    if raw_session is None:
        raw_session = extract_oidc_session_cookie_raw(request, settings)

    rd_host = (urlparse(rd).hostname or "").lower() if rd.startswith("https://") else ""
    portal_host = (settings.portal_domain or "").strip().lower()
    rd_is_absolute_subdomain = bool(rd_host and rd_host != portal_host)
    # Set by subdomain @portal_redirect after auth_request 401. Never bounce back
    # to that Host — FastAPI would_allow can be true while nginx still 401s.
    sub_auth_denied = (request.query_params.get("bastion_sub") or "").strip() == "1"

    def _subdomain_rd_safe() -> bool:
        """Proven accept for absolute rd= — native path preferred (HAR loop)."""
        if not rd_is_absolute_subdomain:
            return True
        if sub_auth_denied:
            return False
        if native_ok and native_subdomain_auth_would_allow(
            db, request, settings, host=rd_host
        ):
            return True
        # Legacy oauth2 / break-glass: presence-only (cannot probe oauth2 here
        # without an outbound call); never bounce on nginx-injected identity alone.
        if request.cookies.get(COOKIE_NAME):
            return True
        return any(
            (name or "").startswith("_oauth2_proxy") or (name or "").startswith("_kc_")
            for name in request.cookies
        )

    if user:
        # Nginx-injected identity on /login (when /login still hits auth_request):
        # only honour absolute subdomain rd when subdomain-auth would accept.
        if rd_is_absolute_subdomain and not _subdomain_rd_safe():
            return RedirectResponse(url="/apps", status_code=302)
        response = RedirectResponse(url=rd, status_code=302)
        if native_ok and raw_session:
            set_oidc_session_cookie(response, raw_session, settings)
        return response

    # Native bastion_session: /auth/login is public (auth_request off).
    # Re-emit with Domain=parent (upgrades host-only cutover cookies). Absolute
    # subdomain rd= only when subdomain-auth would return 200 for that Host.
    if native_ok and raw_session:
        if rd_is_absolute_subdomain and not _subdomain_rd_safe():
            response = RedirectResponse(url="/apps", status_code=302)
            set_oidc_session_cookie(response, raw_session, settings)
            return response
        response = RedirectResponse(url=rd, status_code=302)
        set_oidc_session_cookie(response, raw_session, settings)
        return response

    # Stale/invalid bastion_session + absolute rd would loop via @portal_redirect.
    if rd_is_absolute_subdomain:
        rd = "/apps"

    surface = _login_surface_flags(request, db, settings, rd=rd)
    realm = get_default_idp_realm(db)
    if not realm and not has_active_breakglass_account(db) and not surface["show_native_login"]:
        return RedirectResponse(url=setup_url(rd), status_code=302)

    return render(
        "auth/login.html",
        **_ctx(
            request,
            settings,
            hide_chrome=True,
            **surface,
        ),
    )


@router.post("/auth/breakglass")
async def breakglass_login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    rd: str = Form("/apps"),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    """HTML break-glass login (POST). Native OIDC BFF owns ``POST /auth/login``."""
    # Break-glass is never an end-user: default landing is admin dashboard.
    safe_rd = rd if rd.startswith("/") and not rd.startswith("//") else "/dashboard"
    if safe_rd == "/apps":
        safe_rd = "/dashboard"

    if not has_active_breakglass_account(db):
        raise HTTPException(status_code=403, detail="Initial setup required")

    # Defense in depth: Nginx LAN-restricts /breakglass, but this POST lives under
    # public /auth/ — never verify the break-glass password from a non-LAN IP.
    # Misc policy: optional allow/deny CIDRs override the default RFC1918 gate.
    from app.security.banning.engine import (
        evaluate_login_attempt,
        is_breakglass_ip_allowed,
    )

    client_ip = _client_ip(request)
    if not is_breakglass_ip_allowed(
        db, client_ip, rfc1918_cidrs=settings.rfc1918_cidrs
    ):
        from app.request_client_ip import client_ip_probe

        probe = client_ip_probe(request)
        log_action(
            db,
            actor=username,
            action="breakglass.login_denied_non_lan",
            details={
                "reason": "breakglass_ip_not_allowed",
                "resolved": client_ip or None,
                "x_real_ip": probe.get("x_real_ip"),
                "x_forwarded_for": probe.get("x_forwarded_for"),
                "peer": probe.get("request_client_host"),
            },
            ip_address=client_ip or None,
        )
        ctx = _ctx(
            request,
            settings,
            hide_chrome=True,
            login_error="Identifiants invalides.",
            login_panel="local",
            **_login_surface_flags(request, db, settings, rd=safe_rd),
        )
        return render("auth/login.html", **ctx)

    pre = evaluate_login_attempt(
        db, ip=client_ip, username=username, success=True
    )
    if not pre.allowed:
        ctx = _ctx(
            request,
            settings,
            hide_chrome=True,
            login_error="Identifiants invalides.",
            login_panel="local",
            **_login_surface_flags(request, db, settings, rd=safe_rd),
        )
        return render("auth/login.html", **ctx)

    if not verify_breakglass_password(db, username, password):
        evaluate_login_attempt(
            db, ip=client_ip, username=username, success=False
        )
        from app.breakglass_store import breakglass_account_exists

        # Empty details {} made these rows unreadable in Admin → Logs —
        # unknown_username + a python-httpx UA is a scan/probe, bad_password
        # on a real account is a compromise attempt or a typo.
        log_action(
            db,
            actor=username,
            action="breakglass.login_failed",
            details={
                "via": "form",
                "reason": (
                    "bad_password"
                    if breakglass_account_exists(db, username)
                    else "unknown_username"
                ),
                "user_agent": (request.headers.get("user-agent") or "")[:160] or None,
            },
            ip_address=client_ip or None,
        )
        ctx = _ctx(
            request,
            settings,
            hide_chrome=True,
            login_error="Identifiants invalides.",
            login_panel="local",
            **_login_surface_flags(request, db, settings, rd=safe_rd),
        )
        return render("auth/login.html", **ctx)

    return _breakglass_login_response(username, request, settings, db, safe_rd)


@router.get("/auth/setup")
def setup_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    if get_default_idp_realm(db) or has_active_breakglass_account(db):
        raise HTTPException(status_code=403, detail="Setup is locked")
    rd = resolve_rd(request, portal_domain=settings.portal_domain or "")
    return render(
        "auth/setup.html",
        **_ctx(request, settings, hide_chrome=True, rd=rd),
    )


@router.post("/auth/setup")
async def setup_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    rd: str = Form("/dashboard"),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    if get_default_idp_realm(db) or has_active_breakglass_account(db):
        raise HTTPException(status_code=403, detail="Setup is locked")

    # Setup always creates a break-glass admin — land on dashboard, not /apps.
    safe_rd = rd if rd.startswith("/") and not rd.startswith("//") else "/dashboard"
    if safe_rd == "/apps":
        safe_rd = "/dashboard"
    username = username.strip()
    errors: list[str] = []

    if not username:
        errors.append("Le nom d'utilisateur est requis.")
    if len(password) < _MIN_SETUP_PASSWORD_LEN:
        errors.append(f"Le mot de passe doit contenir au moins {_MIN_SETUP_PASSWORD_LEN} caractères.")
    if password != password_confirm:
        errors.append("Les mots de passe ne correspondent pas.")

    if errors:
        return render(
            "auth/setup.html",
            **_ctx(
                request,
                settings,
                hide_chrome=True,
                rd=safe_rd,
                setup_errors=errors,
                form_username=username,
            ),
        )

    try:
        create_initial_breakglass_account(db, username, password)
    except ValueError:
        raise HTTPException(status_code=403, detail="Setup is locked") from None

    log_action(
        db,
        actor=username,
        action="breakglass.setup",
        ip_address=_client_ip(request),
    )
    return _breakglass_login_response(username, request, settings, db, safe_rd)


@router.get("/auth/sso-start")
def sso_start(
    request: Request,
    settings: Settings = Depends(get_settings),
):
    realm = request.headers.get("X-Portal-Realm-Slug", settings.sso_portal_default_realm_slug)
    rd = request.headers.get("X-Portal-OAuth2-Rd", "/apps")
    redirect_url = f"/oauth2/{realm}/start?rd={rd}"
    return render(
        "auth/sso_redirect.html",
        **_ctx(request, settings, hide_chrome=True, redirect_url=redirect_url),
    )


@router.get("/auth/sso-failed")
def sso_failed(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """
    Explicit SSO failure landing (nginx / oauth2-proxy can redirect here).
    Feeds the same failed_login counters as break-glass.
    """
    from app.security.banning.engine import evaluate_login_attempt

    username = (
        request.query_params.get("username")
        or request.query_params.get("login_hint")
        or "sso"
    ).strip()
    evaluate_login_attempt(
        db,
        ip=_client_ip(request),
        username=username,
        success=False,
    )
    log_action(
        db,
        actor=username,
        action="security.sso_login_failed",
        details={
            "error": (request.query_params.get("error") or "")[:200],
        },
        ip_address=_client_ip(request) or None,
    )
    rd = resolve_rd(request, portal_domain=settings.portal_domain or "")
    surface = _login_surface_flags(request, db, settings, rd=rd)
    show_breakglass = surface["show_breakglass"]
    login_error = (
        "Connexion SSO échouée. Réessayez ou utilisez le break-glass."
        if show_breakglass
        else "Connexion SSO échouée. Réessayez."
    )
    return render(
        "auth/login.html",
        **_ctx(
            request,
            settings,
            hide_chrome=True,
            login_error=login_error,
            **surface,
        ),
    )


@router.get("/logout")
def logout(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Portal UI logout — clear break-glass + native OIDC session.

    The user-menu link is ``GET /logout``. Must revoke break-glass jti and clear
    ``bg_session`` with the same Secure/HttpOnly flags used at set time, otherwise
    the browser keeps the cookie and ``/auth/login`` redirects back to ``/apps``.
    """
    from app.oidc_bff import (
        clear_oidc_session_cookie,
        revoke_oidc_session_from_request,
    )

    response = RedirectResponse(url="/auth/login", status_code=302)
    oidc_actor = revoke_oidc_session_from_request(request, db, settings)
    clear_oidc_session_cookie(response, settings)
    bg_actor = revoke_breakglass_session_from_request(request, db, settings)
    clear_breakglass_cookie(response)
    actor = oidc_actor if oidc_actor and oidc_actor != "unknown" else bg_actor
    if actor and actor != "unknown":
        log_action(
            db,
            actor=actor,
            action="portal_logout",
            ip_address=client_ip_from_request(request) or None,
        )
    return response


def _access_request_page(
    request: Request,
    settings: Settings,
    db: Session,
    *,
    form_error: str | None = None,
    form_success: str | None = None,
    form_values: dict | None = None,
    request_submitted: bool = False,
    submitted: dict | None = None,
):
    from app.rbac.access_request_service import realms_advertising_access_requests

    advertising = realms_advertising_access_requests(db)
    show_form = bool(advertising) and not request_submitted
    return render(
        "auth/access_request.html",
        **_ctx(
            request,
            settings,
            hide_chrome=True,
            access_form_open=bool(advertising),
            request_submitted=bool(request_submitted),
            submitted=submitted or {},
            altcha_enabled=show_form,
            form_error=form_error,
            form_success=form_success,
            form_values=form_values or {},
        ),
    )


@router.get("/auth/altcha/challenge")
def altcha_challenge_get(
    request: Request,
    settings: Settings = Depends(get_settings),
):
    """Issue a fresh ALTCHA PoW challenge for the access-request widget."""
    from fastapi.responses import JSONResponse

    from app.security.access_request_throttle import check_altcha_challenge_rate
    from app.security.altcha_service import create_altcha_challenge

    retry = check_altcha_challenge_rate(client_ip_from_request(request))
    if retry is not None:
        return JSONResponse(
            {"error": "rate_limited"},
            status_code=429,
            headers={"Retry-After": str(int(retry))},
        )
    return JSONResponse(create_altcha_challenge(settings))


@router.get("/auth/access-request")
def access_request_get(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Public self-registration form — realm assigned later by an admin."""
    return _access_request_page(request, settings, db)


@router.post("/auth/access-request")
def access_request_post(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    csrf_token: str = Form(""),
    altcha: str = Form(""),
    username: str = Form(""),
    email: str = Form(""),
    first_name: str = Form(""),
    last_name: str = Form(""),
    organization: str = Form(""),
    message: str = Form(""),
    website: str = Form(""),  # honeypot — must stay empty
):
    from app.rbac.access_request_service import (
        AccessRequestError,
        realms_advertising_access_requests,
        submit_access_request,
    )
    from app.security.access_request_throttle import check_access_request_post_rate
    from app.security.altcha_service import verify_altcha_payload
    from app.web.flash import make_csrf_token

    form_values = {
        "username": (username or "").strip(),
        "email": (email or "").strip(),
        "first_name": (first_name or "").strip(),
        "last_name": (last_name or "").strip(),
        "organization": (organization or "").strip(),
        "message": (message or "").strip(),
    }

    client_ip = client_ip_from_request(request) or None

    # Honeypot: bots that fill hidden fields get a fake success (no DB write).
    if (website or "").strip():
        log_action(
            db,
            actor=(email or "").strip() or "honeypot",
            action="access_request.honeypot",
            details={"path": "/auth/access-request"},
            ip_address=client_ip,
        )
        return _access_request_page(
            request,
            settings,
            db,
            request_submitted=True,
            submitted={
                "username": form_values["username"] or "—",
                "organization": form_values["organization"] or "—",
                "message": form_values["message"],
            },
        )

    retry = check_access_request_post_rate(client_ip)
    if retry is not None:
        log_action(
            db,
            actor=(email or "").strip() or "anonymous",
            action="access_request.rate_limited",
            details={"path": "/auth/access-request", "retry_after": int(retry)},
            ip_address=client_ip,
        )
        return _access_request_page(
            request,
            settings,
            db,
            form_error=(
                "Trop de demandes depuis cette adresse — "
                f"réessayez dans {int(retry)} s."
            ),
            form_values=form_values,
        )

    if not realms_advertising_access_requests(db):
        return _access_request_page(
            request,
            settings,
            db,
            form_error="Les demandes d'accès ne sont pas ouvertes actuellement.",
            form_values=form_values,
        )

    secret = settings.vault_portal_internal_token or "dev-insecure"
    expected = make_csrf_token(request, secret)
    if not csrf_token or not hmac.compare_digest(csrf_token, expected):
        return _access_request_page(
            request,
            settings,
            db,
            form_error="Session expirée — rechargez la page et réessayez.",
            form_values=form_values,
        )

    if not verify_altcha_payload(settings, altcha):
        log_action(
            db,
            actor=(email or "").strip() or "anonymous",
            action="access_request.captcha_failed",
            details={"path": "/auth/access-request", "kind": "altcha"},
            ip_address=client_ip,
        )
        return _access_request_page(
            request,
            settings,
            db,
            form_error="Vérification anti-robot incorrecte ou expirée — réessayez.",
            form_values=form_values,
        )

    try:
        submit_access_request(
            db,
            settings,
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            organization=organization,
            message=message,
            client_ip=client_ip,
        )
    except AccessRequestError as exc:
        return _access_request_page(
            request,
            settings,
            db,
            form_error=str(exc),
            form_values=form_values,
        )

    return _access_request_page(
        request,
        settings,
        db,
        request_submitted=True,
        submitted={
            "username": form_values["username"],
            "organization": form_values["organization"],
            "message": form_values["message"],
        },
    )


@router.get("/health")
def health_page():
    return {"status": "ok"}


# --- Error pages ---


@router.get("/errors/403")
def error_403(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    return render(
        "errors/403.html",
        **_ctx(request, settings, hide_chrome=True),
        status_code=403,
    )


@router.get("/errors/404")
def error_404(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    return render(
        "errors/404.html",
        **_ctx(request, settings, hide_chrome=True),
        status_code=404,
    )


@router.get("/errors/500")
def error_500(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    return render(
        "errors/500.html",
        **_ctx(request, settings, hide_chrome=True),
        status_code=500,
    )


# --- Admin ---


@admin_router.get("/admin")
@admin_router.get("/admin/dashboard")
def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    app_count = db.query(App).count()
    realm_count = db.query(RealmConfig).count()
    metrics = get_dashboard_metrics(db)
    return render(
        "admin/dashboard.html",
        **_ctx(
            request,
            settings,
            app_count=app_count,
            realm_count=realm_count,
            metrics=metrics,
        ),
    )


@admin_router.get("/admin/apps")
def admin_apps_list(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    apps = db.query(App).order_by(App.slug).all()
    realms = db.query(RealmConfig).order_by(RealmConfig.slug).all()
    return render(
        "admin/apps/list.html",
        **_ctx(request, settings, apps=apps, realms=realms),
    )


@admin_router.get("/admin/pending-hosts")
def admin_pending_hosts_list(
    request: Request,
    status: str = Query("pending"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    from app.bastion.pending_host_service import purge_infra_discovery_probes

    purge_infra_discovery_probes(db)
    status_filter = (status or "pending").strip().lower()
    query = db.query(PendingHost)
    if status_filter != "all":
        query = query.filter_by(status=status_filter)
    rows = query.order_by(PendingHost.last_seen_at.desc()).limit(500).all()
    return render(
        "admin/pending_hosts/list.html",
        **_ctx(request, settings, rows=rows, status_filter=status_filter),
    )


@admin_router.get("/admin/pending-hosts/{host_id}/approve")
def admin_pending_host_approve_form(
    host_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    row = db.query(PendingHost).filter_by(id=host_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Hôte introuvable")
    return render(
        "admin/pending_hosts/approve.html",
        **_ctx(
            request,
            settings,
            row=row,
            form_values={
                "slug": suggest_slug(row.hostname),
                "label": row.hostname,
                "upstream_url": "",
            },
            errors={},
        ),
    )


@admin_router.post("/admin/pending-hosts/{host_id}/approve")
def admin_pending_host_approve_post(
    host_id: int,
    request: Request,
    slug: str = Form(...),
    label: str = Form(...),
    upstream_url: str = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    row = db.query(PendingHost).filter_by(id=host_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Hôte introuvable")
    form_values = {"slug": slug, "label": label, "upstream_url": upstream_url}
    try:
        _, app = approve_pending_host(
            db,
            settings,
            host_id=host_id,
            actor=user.email,
            upstream_url=upstream_url,
            slug=slug,
            label=label,
        )
    except ValueError as exc:
        return render(
            "admin/pending_hosts/approve.html",
            **_ctx(
                request,
                settings,
                row=row,
                form_values=form_values,
                errors={"_form": str(exc)},
            ),
        )
    response = RedirectResponse(url="/admin/pending-hosts?status=approved", status_code=302)
    flash_redirect(
        response,
        f"Domaine « {app.public_fqdn} » approuvé → app {app.slug}. "
        "bastion-nginx recharge la conf exportée sous quelques secondes "
        "(sinon Apply infra / redémarrer le conteneur nginx).",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.post("/admin/pending-hosts/{host_id}/reject")
def admin_pending_host_reject_post(
    host_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    try:
        row = reject_pending_host(db, host_id=host_id, actor=user.email)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    response = RedirectResponse(url="/admin/pending-hosts?status=rejected", status_code=302)
    flash_redirect(
        response,
        f"Domaine « {row.hostname} » rejeté.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.get("/admin/pending-users")
def admin_pending_users_list(
    request: Request,
    status: str = Query("pending"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    from app.web.pending_user_service import discover_recent_first_logins

    discover_recent_first_logins(db)
    db.commit()
    status_filter = (status or "pending").strip().lower()
    query = db.query(PendingUser)
    if status_filter != "all":
        query = query.filter_by(status=status_filter)
    rows = query.order_by(PendingUser.last_seen_at.desc()).limit(500).all()
    realms_by_slug = {
        r.slug: r.id for r in db.query(RealmConfig).all()
    }
    return render(
        "admin/pending_users/list.html",
        **_ctx(
            request,
            settings,
            rows=rows,
            status_filter=status_filter,
            realms_by_slug=realms_by_slug,
        ),
    )


@admin_router.post("/admin/pending-users/{user_id}/approve")
def admin_pending_user_approve_post(
    user_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.web.pending_user_service import acknowledge_pending_user

    try:
        row = acknowledge_pending_user(
            db, user_id=user_id, actor=user.email, status="approved"
        )
        db.commit()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    response = RedirectResponse(url="/admin/pending-users?status=approved", status_code=302)
    flash_redirect(
        response,
        f"Première connexion « {row.user_email} » validée "
        "(ne coupe pas l’accès IdP — ouvrez la fiche pour attribuer des droits Bastion).",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.post("/admin/pending-users/{user_id}/reject")
def admin_pending_user_reject_post(
    user_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.web.pending_user_service import acknowledge_pending_user

    try:
        row = acknowledge_pending_user(
            db, user_id=user_id, actor=user.email, status="rejected"
        )
        db.commit()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    response = RedirectResponse(url="/admin/pending-users?status=rejected", status_code=302)
    flash_redirect(
        response,
        f"Première connexion « {row.user_email} » marquée rejetée "
        "(session Keycloak non révoquée automatiquement — utilisez Sessions si besoin).",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.get("/admin/access-requests")
def admin_access_requests_list(
    request: Request,
    status: str = Query("pending"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    from app.rbac.access_request_service import (
        list_access_requests,
        realms_for_access_request_approve,
    )

    status_filter = (status or "pending").strip().lower()
    rows = list_access_requests(db, status=status_filter)
    return render(
        "admin/access_requests/list.html",
        **_ctx(
            request,
            settings,
            rows=rows,
            status_filter=status_filter,
            approve_realms=realms_for_access_request_approve(db),
        ),
    )


@admin_router.post("/admin/access-requests/{request_id}/approve")
async def admin_access_request_approve_post(
    request_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    realm_id: str = Form(""),
    send_credentials: str = Form(""),
):
    from app.rbac.access_request_service import (
        AccessRequestError,
        approve_access_request,
    )

    want_email = send_credentials.strip().lower() in ("1", "true", "on", "yes")
    secret = settings.vault_portal_internal_token or "dev"
    try:
        rid = int((realm_id or "").strip())
    except ValueError:
        response = RedirectResponse(
            url="/admin/access-requests?status=pending", status_code=302
        )
        flash_redirect(response, "Choisissez un realm cible.", "error", secret)
        return response
    try:
        row, account, step_errors = await approve_access_request(
            db,
            settings,
            request_id=request_id,
            actor=user.email,
            realm_id=rid,
            ip_address=request.headers.get("X-Real-IP")
            or (request.client.host if request.client else None),
            send_credentials=want_email,
        )
    except AccessRequestError as exc:
        response = RedirectResponse(
            url="/admin/access-requests?status=pending", status_code=302
        )
        flash_redirect(response, str(exc), "error", secret)
        return response

    msg = (
        f"Demande « {row.username} » approuvée — compte {account.username} "
        f"({account.status})."
    )
    category = "success"
    if step_errors:
        msg = f"{msg} Avertissements : {'; '.join(step_errors)}"
        category = "warning"
    response = RedirectResponse(
        url="/admin/access-requests?status=approved", status_code=302
    )
    flash_redirect(response, msg, category, secret)
    return response


@admin_router.post("/admin/access-requests/{request_id}/reject")
def admin_access_request_reject_post(
    request_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    notes: str = Form(""),
):
    from app.rbac.access_request_service import (
        AccessRequestError,
        reject_access_request,
    )

    secret = settings.vault_portal_internal_token or "dev"
    try:
        row = reject_access_request(
            db,
            request_id=request_id,
            actor=user.email,
            notes=notes,
            ip_address=request.headers.get("X-Real-IP")
            or (request.client.host if request.client else None),
        )
    except AccessRequestError as exc:
        response = RedirectResponse(
            url="/admin/access-requests?status=pending", status_code=302
        )
        flash_redirect(response, str(exc), "error", secret)
        return response

    response = RedirectResponse(
        url="/admin/access-requests?status=rejected", status_code=302
    )
    flash_redirect(
        response,
        f"Demande « {row.username} » rejetée.",
        "success",
        secret,
    )
    return response


@admin_router.get("/admin/apps/create")
def admin_apps_create(
    request: Request,
    settings: Settings = Depends(get_settings),
):
    return render(
        "admin/apps/create.html",
        **_ctx(
            request,
            settings,
            form_values={
                "slug": "",
                "label": "",
                "upstream_url": "",
                "access_mode": "sso_gate",
                "public_fqdn": "",
                "description": "",
                "allow_activesync": False,
                "upstream_tls_verify": False,
                **_auth_form_values(),
            },
            errors={},
        ),
    )


@admin_router.post("/admin/apps/create")
def admin_apps_create_post(
    request: Request,
    slug: str = Form(...),
    label: str = Form(...),
    upstream_url: str = Form(...),
    access_mode: str = Form("sso_gate"),
    public_fqdn: str = Form(""),
    description: str = Form(""),
    allow_activesync: str | None = Form(None),
    upstream_tls_verify: str | None = Form(None),
    auth_mode: str = Form("sso"),
    login_form_url: str = Form(""),
    login_username_field: str = Form("username"),
    login_password_field: str = Form("password"),
    login_http_method: str = Form("POST"),
    login_extra_fields: str = Form(""),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    mode = normalize_access_mode(access_mode)
    fqdn = public_fqdn.strip() or None
    desc = _normalize_description(description)
    auth_values = _auth_form_values(
        auth_mode,
        login_form_url,
        login_username_field,
        login_password_field,
        login_http_method,
        login_extra_fields,
    )
    form_values = {
        "slug": slug,
        "label": label,
        "upstream_url": upstream_url,
        "access_mode": mode,
        "public_fqdn": public_fqdn,
        "description": description,
        "allow_activesync": allow_activesync == "on",
        "upstream_tls_verify": upstream_tls_verify == "on",
        **auth_values,
    }
    errors = validate_app_access_fields(mode, upstream_url, fqdn)
    errors.update(
        _validate_auth_fields(
            mode,
            auth_mode,
            login_form_url,
            login_username_field,
            login_password_field,
            login_http_method,
            login_extra_fields,
        )
    )
    if len((description or "").strip()) > _DESC_MAX:
        errors["description"] = f"La description ne doit pas dépasser {_DESC_MAX} caractères."
    if db.query(App).filter_by(slug=slug).first():
        errors["slug"] = f"Le slug « {slug} » existe déjà."
    if errors:
        return render(
            "admin/apps/create.html",
            **_ctx(request, settings, form_values=form_values, errors=errors),
        )
    app = App(
        slug=slug,
        label=label,
        upstream_url=upstream_url,
        access_mode=mode,
        public_fqdn=fqdn,
        description=desc,
        allow_activesync=allow_activesync == "on" and mode == "subdomain_proxy",
        upstream_tls_verify=upstream_tls_verify == "on" and mode != "sso_gate",
    )
    _apply_auth_config(
        app,
        auth_mode=auth_mode,
        login_form_url=login_form_url,
        login_username_field=login_username_field,
        login_password_field=login_password_field,
        login_http_method=login_http_method,
        login_extra_fields=login_extra_fields,
        credential_mode="shared",
    )
    db.add(app)
    db.commit()
    _warn_if_fqdn_cookie_domain_incompatible(
        access_mode=mode,
        public_fqdn=fqdn,
        portal_domain=settings.portal_domain,
        app_slug=slug,
    )
    export_app_catalogue_files(db, settings)
    log_action(db, actor=user.email, action="app.created", target=slug)
    response = RedirectResponse(url=f"/admin/apps/{slug}/edit", status_code=302)
    flash_redirect(
        response,
        f"Application '{label}' créée. Vous pouvez ajouter un logo.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.get("/admin/apps/{slug}/edit")
def admin_apps_edit(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    rbac_grant_count = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.resource_type == "application",
            AccessGrant.application_id == app.id,
        )
        .count()
    )
    return render(
        "admin/apps/edit.html",
        **_ctx(
            request,
            settings,
            app=app,
            errors={},
            logo_url=logo_public_url(app),
            vault_enabled=vault_enabled_for_app(app.auth_mode, app.robotic_driver),
            rbac_grant_count=rbac_grant_count,
            provisioning_driver_labels=PROVISIONING_DRIVER_LABELS,
        ),
    )


@admin_router.post("/admin/apps/{slug}/edit")
def admin_apps_edit_post(
    slug: str,
    request: Request,
    label: str = Form(...),
    upstream_url: str = Form(...),
    access_mode: str = Form("sso_gate"),
    public_fqdn: str = Form(""),
    description: str = Form(""),
    enabled: str | None = Form(None),
    allow_activesync: str | None = Form(None),
    upstream_tls_verify: str | None = Form(None),
    auth_mode: str = Form("sso"),
    login_form_url: str = Form(""),
    login_username_field: str = Form("username"),
    login_password_field: str = Form("password"),
    login_http_method: str = Form("POST"),
    login_extra_fields: str = Form(""),
    credential_mode: str = Form("shared"),
    identity_format: str = Form("email"),
    injected_cookie_scope: str = Form("host_only"),
    provisioning_driver: str = Form(""),
    crushftp_admin_base_url: str = Form(""),
    crushftp_admin_server_group: str = Form(""),
    crushftp_admin_username: str = Form(""),
    crushftp_admin_password: str = Form(""),
    crushftp_vfs_base_path: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    mode = normalize_access_mode(access_mode)
    fqdn = public_fqdn.strip() or None
    desc = _normalize_description(description)
    errors = validate_app_access_fields(mode, upstream_url, fqdn)
    errors.update(
        _validate_auth_fields(
            mode,
            auth_mode,
            login_form_url,
            login_username_field,
            login_password_field,
            login_http_method,
            login_extra_fields,
        )
    )
    if len((description or "").strip()) > _DESC_MAX:
        errors["description"] = f"La description ne doit pas dépasser {_DESC_MAX} caractères."
    if errors:
        app.label = label
        app.upstream_url = upstream_url
        app.access_mode = mode
        app.public_fqdn = fqdn
        app.description = desc
        app.allow_activesync = allow_activesync == "on" and mode == "subdomain_proxy"
        app.upstream_tls_verify = upstream_tls_verify == "on" and mode != "sso_gate"
        app.provisioning_driver = normalize_provisioning_driver(provisioning_driver)
        # Re-display CrushFTP admin fields from the form (do not encrypt yet).
        app.crushftp_admin_base_url = (crushftp_admin_base_url or "").strip() or None
        app.crushftp_admin_server_group = (
            (crushftp_admin_server_group or "").strip() or None
        )
        app.crushftp_admin_username = (crushftp_admin_username or "").strip() or None
        app.crushftp_vfs_base_path = (
            (crushftp_vfs_base_path or "").strip().replace("\\", "/").rstrip("/") or None
        )
        _apply_auth_config(
            app,
            auth_mode=auth_mode,
            login_form_url=login_form_url,
            login_username_field=login_username_field,
            login_password_field=login_password_field,
            login_http_method=login_http_method,
            login_extra_fields=login_extra_fields,
            credential_mode=credential_mode,
            identity_format=identity_format,
            injected_cookie_scope=injected_cookie_scope,
        )
        rbac_grant_count = (
            db.query(AccessGrant)
            .filter(
                AccessGrant.resource_type == "application",
                AccessGrant.application_id == app.id,
            )
            .count()
        )
        return render(
            "admin/apps/edit.html",
            **_ctx(
                request,
                settings,
                app=app,
                errors=errors,
                logo_url=logo_public_url(app),
                vault_enabled=vault_enabled_for_app(app.auth_mode, app.robotic_driver),
                rbac_grant_count=rbac_grant_count,
                provisioning_driver_labels=PROVISIONING_DRIVER_LABELS,
            ),
        )
    provision_driver = normalize_provisioning_driver(provisioning_driver)
    crush_errors: dict[str, str] = {}
    if provision_driver == "crushftp":
        crush_errors = _apply_crushftp_admin_config(
            app,
            settings,
            crushftp_admin_base_url=crushftp_admin_base_url,
            crushftp_admin_server_group=crushftp_admin_server_group,
            crushftp_admin_username=crushftp_admin_username,
            crushftp_admin_password=crushftp_admin_password,
            crushftp_vfs_base_path=crushftp_vfs_base_path,
        )
    if crush_errors:
        errors.update(crush_errors)
        app.label = label
        app.upstream_url = upstream_url
        app.access_mode = mode
        app.public_fqdn = fqdn
        app.description = desc
        app.allow_activesync = allow_activesync == "on" and mode == "subdomain_proxy"
        app.upstream_tls_verify = upstream_tls_verify == "on" and mode != "sso_gate"
        app.provisioning_driver = normalize_provisioning_driver(provisioning_driver)
        _apply_auth_config(
            app,
            auth_mode=auth_mode,
            login_form_url=login_form_url,
            login_username_field=login_username_field,
            login_password_field=login_password_field,
            login_http_method=login_http_method,
            login_extra_fields=login_extra_fields,
            credential_mode=credential_mode,
            identity_format=identity_format,
            injected_cookie_scope=injected_cookie_scope,
        )
        rbac_grant_count = (
            db.query(AccessGrant)
            .filter(
                AccessGrant.resource_type == "application",
                AccessGrant.application_id == app.id,
            )
            .count()
        )
        return render(
            "admin/apps/edit.html",
            **_ctx(
                request,
                settings,
                app=app,
                errors=errors,
                logo_url=logo_public_url(app),
                vault_enabled=vault_enabled_for_app(app.auth_mode, app.robotic_driver),
                rbac_grant_count=rbac_grant_count,
                provisioning_driver_labels=PROVISIONING_DRIVER_LABELS,
            ),
        )
    app.label = label
    app.upstream_url = upstream_url
    app.access_mode = mode
    app.public_fqdn = fqdn
    app.description = desc
    app.enabled = enabled == "on"
    app.allow_activesync = allow_activesync == "on" and mode == "subdomain_proxy"
    app.upstream_tls_verify = upstream_tls_verify == "on" and mode != "sso_gate"
    app.provisioning_driver = normalize_provisioning_driver(provisioning_driver)
    _apply_auth_config(
        app,
        auth_mode=auth_mode,
        login_form_url=login_form_url,
        login_username_field=login_username_field,
        login_password_field=login_password_field,
        login_http_method=login_http_method,
        login_extra_fields=login_extra_fields,
        credential_mode=credential_mode,
        identity_format=identity_format,
        injected_cookie_scope=injected_cookie_scope,
    )
    db.commit()
    _warn_if_fqdn_cookie_domain_incompatible(
        access_mode=mode,
        public_fqdn=fqdn,
        portal_domain=settings.portal_domain,
        app_slug=slug,
    )
    exported = export_app_catalogue_files(db, settings)
    apply_req = request_host_apply(settings, exported_files=len(exported))
    apply_state = wait_for_host_apply(settings, timeout_sec=8.0)
    log_action(
        db,
        actor=user.email,
        action="app.updated",
        target=slug,
        details={
            "access_mode": mode,
            "public_fqdn": fqdn,
            "host_apply_requested": bool(apply_req.get("ok")),
            "host_apply_status": apply_state.get("status"),
        },
    )
    log_action(
        db,
        actor=user.email,
        action=f"infrastructure.apply.{apply_state.get('status', 'unknown')}",
        target=slug,
        details={
            "source": "app.updated",
            "application_id": app.id,
            "application_slug": slug,
            "requested": bool(apply_req.get("ok")),
            "request_path": apply_req.get("path"),
            "status_path": apply_state.get("status_path"),
            "log_path": apply_state.get("log_path"),
            "request_pending": apply_state.get("request_pending"),
        },
    )
    response = RedirectResponse(url="/admin/apps", status_code=302)
    if apply_state.get("status") == "ok":
        msg = (
            f"Application '{label}' mise à jour. "
            "Export et apply hôte confirmés."
        )
        category = "success"
    elif apply_state.get("status") == "error":
        msg = (
            f"Application '{label}' mise à jour, mais l'apply hôte a échoué. "
            "Voir Admin → Infrastructure pour le log détaillé."
        )
        category = "error"
    else:
        msg = (
            f"Application '{label}' mise à jour. "
            "Export demandé ; apply hôte toujours en attente."
        )
        category = "error"
    flash_redirect(response, msg, category, settings.vault_portal_internal_token or "dev")
    return response


class _VaultCredentialBody(BaseModel):
    robotic_username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class _AnalyzeLoginFormBody(BaseModel):
    url: str = Field(min_length=1)
    tls_verify: bool = False


@admin_router.post("/admin/apps/analyze-login-form")
async def admin_analyze_login_form(
    body: _AnalyzeLoginFormBody,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    """Fetch a remote login page and detect form field names (no credentials sent)."""
    from app.bastion.login_form_analyzer import (
        AnalyzeLoginFormError,
        analyze_login_form_url,
    )

    try:
        result = await analyze_login_form_url(
            body.url.strip(),
            tls_verify=bool(body.tls_verify),
        )
    except AnalyzeLoginFormError as exc:
        log_action(
            db,
            actor=user.email,
            action="app.login_form.analyzed",
            target=(body.url or "").strip()[:500],
            details={"error": exc.error, "forms_found": 0},
            ip_address=_client_ip(request),
        )
        return JSONResponse(
            {"error": exc.error, "message": exc.message},
            status_code=exc.status_code,
        )
    log_action(
        db,
        actor=user.email,
        action="app.login_form.analyzed",
        target=(body.url or "").strip()[:500],
        details={
            "forms_found": result["forms_found"],
            "fetched_url": result.get("fetched_url"),
            "actions": [f.get("action") for f in result.get("forms", [])],
        },
        ip_address=_client_ip(request),
    )
    return result


@admin_router.get("/admin/apps/{slug}/credential")
def admin_app_credential_read(
    slug: str,
    db: Session = Depends(get_db),
):
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    cred = get_app_credential(db, slug)
    if cred is None:
        raise HTTPException(status_code=404, detail=f"No credential for app '{slug}'")
    return {
        "robotic_username": cred.robotic_username,
        "is_active": cred.is_active,
        "created_at": cred.created_at,
        "rotated_at": cred.rotated_at,
    }


@admin_router.post("/admin/apps/{slug}/crushftp/sync-companies")
async def admin_app_crushftp_sync_companies(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Import CrushFTP company folders under vfs base as RBAC/Keycloak société groups."""
    from app.rbac.account_service import (
        AccountCreationError,
        sync_company_groups_from_crushftp,
    )

    wants_json = "application/json" in (request.headers.get("accept") or "")

    def _err(msg: str, status: int = 400):
        if wants_json:
            return JSONResponse(
                {"ok": False, "errors": {"_form": msg}},
                status_code=status,
            )
        response = RedirectResponse(url="/admin/apps", status_code=302)
        flash_redirect(
            response,
            msg,
            "error",
            settings.vault_portal_internal_token or "dev",
        )
        return response

    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        return _err("Application introuvable", 404)

    # Parse form manually so JSON Accept + multipart never 500 on validation.
    try:
        form = await request.form()
        realm_raw = form.get("realm_id")
        realm_id = int(str(realm_raw)) if realm_raw not in (None, "") else None
    except Exception:
        return _err("Paramètres d’import invalides (realm).")
    if not realm_id:
        return _err("Choisissez un realm cible.")

    realm = db.query(RealmConfig).filter_by(id=realm_id).first()
    if not realm:
        return _err("Realm introuvable", 404)

    actor = (getattr(user, "email", None) or getattr(user, "username", None) or "admin")
    try:
        summary = await sync_company_groups_from_crushftp(
            db,
            settings,
            app=app,
            realm=realm,
            actor=str(actor),
            ip_address=_client_ip(request),
        )
    except AccountCreationError as exc:
        return _err(str(exc))
    except Exception:
        logger.exception("crushftp sync-companies failed app=%s realm=%s", slug, realm.slug)
        return _err(
            "Erreur lors de l’import CrushFTP (voir logs serveur).",
            status=500 if not wants_json else 400,
        )

    if wants_json:
        return JSONResponse({"ok": True, **summary})

    created_n = len(summary.get("created") or [])
    existing_n = len(summary.get("existing") or [])
    found_n = len(summary.get("folders_found") or [])
    err_n = len(summary.get("errors") or [])
    msg = (
        f"Sociétés CrushFTP synchronisées ({realm.slug}) : "
        f"{found_n} dossier(s), {created_n} créé(s), {existing_n} déjà présent(s)"
    )
    if err_n:
        msg += f", {err_n} erreur(s)"
    category = "warning" if err_n else "success"
    response = RedirectResponse(url="/admin/apps", status_code=302)
    flash_redirect(
        response,
        msg,
        category,
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.post("/admin/apps/{slug}/credential")
def admin_app_credential_save(
    slug: str,
    body: _VaultCredentialBody,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    if normalize_credential_mode(app.credential_mode) in (
        "individual_required",
        "identite_utilisateur",
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Compte partagé désactivé — cette application n'utilise pas le "
                "credential vault partagé dans ce mode."
            ),
        )
    try:
        cred = set_app_credential(
            db,
            slug,
            body.robotic_username.strip(),
            body.password,
            settings,
            actor=user.email,
            ip_address=_client_ip(request),
        )
    except EncryptionNotConfiguredError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except VaultError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "robotic_username": cred.robotic_username,
        "is_active": cred.is_active,
    }


@admin_router.post("/admin/apps/{slug}/credential/test")
async def admin_app_credential_test(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    if wait := throttle_retry_after("app_credential", slug, min_interval_seconds=5):
        return JSONResponse(
            {"ok": False, "error": f"Trop de tests — réessayez dans {wait:.0f}s"},
            status_code=429,
        )
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    result = await test_app_credential_connection(db, app, settings)
    log_action(
        db,
        actor=user.email,
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


@admin_router.get("/admin/apps/{slug}/users/{keycloak_user_id}/credential")
def admin_user_app_credential_read(
    slug: str,
    keycloak_user_id: str,
    db: Session = Depends(get_db),
):
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    override = has_user_override(db, slug, keycloak_user_id)
    user_cred = get_user_credential(db, slug, keycloak_user_id) if override else None
    shared = get_app_credential(db, slug)
    return {
        "app_slug": slug,
        "keycloak_user_id": keycloak_user_id,
        "has_override": override,
        "credential_source": "user_override" if override else "shared",
        "robotic_username": (
            user_cred.robotic_username if user_cred is not None else (
                shared.robotic_username if shared is not None else None
            )
        ),
        "shared_available": shared is not None and bool(shared.is_active),
    }


@admin_router.post("/admin/apps/{slug}/users/{keycloak_user_id}/credential")
async def admin_user_app_credential_save(
    slug: str,
    keycloak_user_id: str,
    body: _VaultCredentialBody,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    try:
        cred = set_user_credential(
            db,
            slug,
            keycloak_user_id,
            body.robotic_username.strip(),
            body.password,
            settings,
            actor=user.email,
            ip_address=_client_ip(request),
        )
    except EncryptionNotConfiguredError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except VaultError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Push the new credential to the target app when a bastion account + driver exist.
    sync_detail = None
    sync_status = None
    from app.models import BastionAccount
    from app.rbac.account_service import sync_vault_credential_to_app

    account = (
        db.query(BastionAccount)
        .filter_by(keycloak_user_id=keycloak_user_id)
        .first()
    )
    if account is not None and getattr(app, "provisioning_driver", None):
        result = await sync_vault_credential_to_app(
            db,
            settings,
            account=account,
            app=app,
            actor=user.email,
            ip_address=_client_ip(request),
            group_names=[account.organization] if account.organization else None,
        )
        sync_status = result.status
        sync_detail = result.detail

    return {
        "ok": True,
        "has_override": True,
        "robotic_username": cred.robotic_username,
        "credential_source": "user_override",
        "app_sync_status": sync_status,
        "app_sync_detail": sync_detail,
    }


@admin_router.delete("/admin/apps/{slug}/users/{keycloak_user_id}/credential")
def admin_user_app_credential_delete(
    slug: str,
    keycloak_user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.rbac.governance_service import user_can_module_action
    from app.web.user_context import is_portal_admin

    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    if not user_can_module_action(
        db,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
        module_key="secret_vault",
        action="can_delete",
        is_portal_admin=is_portal_admin(user, db, settings),
    ):
        raise HTTPException(
            status_code=403,
            detail="Permission gouvernance secret_vault.can_delete refusée",
        )
    deleted = delete_user_credential(
        db,
        slug,
        keycloak_user_id,
        actor=user.email,
        ip_address=_client_ip(request),
    )
    return {"ok": True, "deleted": deleted, "has_override": False, "credential_source": "shared"}


@admin_router.post("/admin/apps/{slug}/users/{keycloak_user_id}/credential/test")
async def admin_user_app_credential_test(
    slug: str,
    keycloak_user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    throttle_id = f"{slug}:{keycloak_user_id}"
    if wait := throttle_retry_after("user_app_credential", throttle_id, min_interval_seconds=5):
        return JSONResponse(
            {"ok": False, "error": f"Trop de tests — réessayez dans {wait:.0f}s"},
            status_code=429,
        )
    app = db.query(App).filter_by(slug=slug).first()
    if not app:
        raise HTTPException(status_code=404)
    result = await test_app_credential_connection(
        db, app, settings, keycloak_user_id=keycloak_user_id
    )
    log_action(
        db,
        actor=user.email,
        action="credential.user.test",
        target=f"app:{slug}/user:{keycloak_user_id}",
        details={
            "resource_type": result.resource_type,
            "resource_id": slug,
            "keycloak_user_id": keycloak_user_id,
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


@admin_router.post("/admin/apps/{app_id}/logo")
async def admin_app_logo_upload(
    app_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    """Upload / replace app logo (admin only). Content-sniffed PNG/JPEG/WEBP, max 512 KB."""
    app = db.query(App).filter_by(id=app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application introuvable")
    raw = await file.read()
    try:
        save_app_logo(app, raw)
    except LogoValidationError as exc:
        return JSONResponse({"ok": False, "detail": str(exc)}, status_code=400)
    db.commit()
    log_action(db, actor=user.email, action="app.logo_updated", target=app.slug)
    return {"ok": True, "logo_url": logo_public_url(app)}


@admin_router.delete("/admin/apps/{app_id}/logo")
def admin_app_logo_delete(
    app_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    """Remove logo and fall back to tile_icon / generic icon on the portal."""
    app = db.query(App).filter_by(id=app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application introuvable")
    clear_app_logo(app)
    db.commit()
    log_action(db, actor=user.email, action="app.logo_removed", target=app.slug)
    return {"ok": True}


@admin_router.get("/admin/rbac/overview")
async def admin_rbac_overview(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """RBAC dashboard — entry point for cross-links (see docs/rbac-information-architecture.md)."""
    from sqlalchemy import func

    from app.models import AccessGrant, BastionAccount, GroupAppCredential
    from app.rbac.governance_service import excess_permission_alerts
    from app.rbac.users_stats_service import fetch_user_directory_stats

    realms = (
        db.query(RealmConfig)
        .filter(RealmConfig.enabled.is_(True))
        .order_by(RealmConfig.slug)
        .all()
    )
    selected = realms[0] if realms else None
    user_stats = await fetch_user_directory_stats(db, selected, settings)
    groups_all = db.query(func.count(RBACGroup.id)).scalar() or 0
    groups_empty = (
        db.query(func.count(RBACGroup.id))
        .filter(func.coalesce(RBACGroup.member_count, 0) == 0)
        .scalar()
        or 0
    )
    groups_with = max(0, int(groups_all) - int(groups_empty))
    bastion_count = db.query(func.count(BastionAccount.id)).scalar() or 0
    direct_grant_users = (
        db.query(func.count(func.distinct(AccessGrant.keycloak_user_id)))
        .filter(
            AccessGrant.subject_type == "user",
            AccessGrant.keycloak_user_id.isnot(None),
        )
        .scalar()
        or 0
    )
    shared_creds = db.query(func.count(GroupAppCredential.id)).scalar() or 0
    alerts = excess_permission_alerts(db)
    return render(
        "admin/rbac/overview.html",
        **_ctx(
            request,
            settings,
            active_tab="overview",
            realms=realms,
            selected_realm=selected,
            user_stats=user_stats.as_dict(),
            group_stats={
                "total": int(groups_all),
                "empty": int(groups_empty),
                "with_members": int(groups_with),
                "alerts": len(alerts),
            },
            bastion_accounts_total=int(bastion_count),
            direct_grant_users=int(direct_grant_users),
            shared_credentials_total=int(shared_creds),
            excess_alerts=alerts,
        ),
    )


@admin_router.get("/admin/rbac")
async def admin_rbac(
    request: Request,
    q: str = Query(""),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=10, le=200),
    include_empty: str | None = Query(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    from app.rbac.governance_service import (
        excess_permission_alerts,
        role_distribution_summary,
    )
    from app.rbac.permission_seed import seed_governance_rbac
    from app.models import AccessGrant, GroupAppCredential

    from sqlalchemy import func

    seed_governance_rbac(db)
    db.commit()

    realms = db.query(RealmConfig).order_by(RealmConfig.slug).all()
    apps = db.query(App).order_by(App.label).all()
    realms_by_id = {r.id: r for r in realms}

    role_grants = {
        g.rbac_group_id: g
        for g in db.query(AccessGrant)
        .filter_by(subject_type="group", resource_type="rbac_role")
        .all()
        if g.rbac_group_id
    }

    groups_all = db.query(func.count(RBACGroup.id)).scalar() or 0
    groups_empty = (
        db.query(func.count(RBACGroup.id))
        .filter(func.coalesce(RBACGroup.member_count, 0) == 0)
        .scalar()
        or 0
    )
    groups_synced = (
        db.query(func.count(RBACGroup.id))
        .filter(RBACGroup.keycloak_group_id.isnot(None))
        .scalar()
        or 0
    )
    excess_alerts = excess_permission_alerts(db)
    show_empty = (include_empty or "").strip().lower() in ("1", "true", "on", "yes")

    query = db.query(RBACGroup)
    needle = " ".join((q or "").split()).strip()
    if needle:
        like = f"%{needle}%"
        query = query.filter(
            (RBACGroup.name.ilike(like))
            | (RBACGroup.path.ilike(like))
            | (RBACGroup.group_tag.ilike(like))
            | (RBACGroup.realm_slug.ilike(like))
            | (RBACGroup.description.ilike(like))
        )
    if not show_empty:
        query = query.filter(func.coalesce(RBACGroup.member_count, 0) > 0)
    total = query.count()
    total_pages = max(1, (total + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * per_page
    groups = (
        query.order_by(
            func.coalesce(RBACGroup.member_count, 0).desc(),
            RBACGroup.name.asc(),
        )
        .offset(offset)
        .limit(per_page)
        .all()
    )

    group_ids = [g.id for g in groups]
    grant_counts: dict[int, int] = {}
    cred_counts: dict[int, int] = {}
    if group_ids:
        for gid, cnt in (
            db.query(AccessGrant.rbac_group_id, func.count(AccessGrant.id))
            .filter(
                AccessGrant.subject_type == "group",
                AccessGrant.rbac_group_id.in_(group_ids),
            )
            .group_by(AccessGrant.rbac_group_id)
            .all()
        ):
            if gid is not None:
                grant_counts[int(gid)] = int(cnt)
        for gid, cnt in (
            db.query(GroupAppCredential.rbac_group_id, func.count(GroupAppCredential.id))
            .filter(GroupAppCredential.rbac_group_id.in_(group_ids))
            .group_by(GroupAppCredential.rbac_group_id)
            .all()
        ):
            if gid is not None:
                cred_counts[int(gid)] = int(cnt)

    group_rows: list[dict] = []
    for g in groups:
        realm = realms_by_id.get(g.realm_id) if g.realm_id else None
        grant = role_grants.get(g.id)
        mode = "limited"
        role_id = None
        if grant and grant.access_level == "manage":
            mode = "total"
            role_id = grant.rbac_role_id
        elif grant:
            role_id = grant.rbac_role_id
        group_rows.append(
            {
                "id": g.id,
                "name": g.name,
                "path": g.path,
                "realm_slug": (realm.slug if realm else g.realm_slug),
                "group_tag": g.group_tag,
                "description": g.description,
                "member_count": int(g.member_count or 0),
                "role_mode": mode,
                "rbac_role_id": role_id,
                "grant_count": grant_counts.get(g.id, 0),
                "credential_count": cred_counts.get(g.id, 0),
            }
        )

    range_start = offset + 1 if total else 0
    range_end = min(offset + len(group_rows), total)

    return render(
        "admin/rbac.html",
        **_ctx(
            request,
            settings,
            realms=realms,
            realms_by_id=realms_by_id,
            groups=groups,
            apps=apps,
            group_rows=group_rows,
            group_cards=group_rows,  # backward-compatible alias
            groups_q=needle,
            groups_page=page,
            groups_per_page=per_page,
            groups_total=total,
            groups_total_pages=total_pages,
            groups_range_start=range_start,
            groups_range_end=range_end,
            groups_include_empty=show_empty,
            group_stats={
                "total": int(groups_all),
                "empty": int(groups_empty),
                "synced": int(groups_synced),
                "alerts": len(excess_alerts),
            },
            role_distribution=role_distribution_summary(db),
            excess_alerts=excess_alerts,
            active_tab="groups",
        ),
    )


@admin_router.get("/admin/security")
def admin_security(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    from app.breakglass import resolve_breakglass_signing_secret_with_source
    from app.breakglass_secret_service import build_breakglass_secret_status
    from app.db_cipher import get_db_encryption_status
    from app.portal_settings_service import get_subdomain_sso_enabled
    from app.security.banning.service import (
        get_or_create_policy,
        list_active_bans,
        list_allowlist,
        list_ban_rules,
    )
    from app.vault.encryption_key_store import get_vault_key_status
    from app.web.container_logs_settings import ensure_container_logs_settings
    from app.siem.settings_service import ensure_siem_settings, public_status as siem_public_status

    subdomain_apps = (
        db.query(App)
        .filter(App.access_mode == "subdomain_proxy", App.enabled.is_(True))
        .order_by(App.label)
        .all()
    )
    vault_status = get_vault_key_status(db, settings)
    db_encryption = get_db_encryption_status(settings)
    from app.db.hot_store import get_hot_store_status

    hot_store = get_hot_store_status(db, settings)
    bg_secret, bg_source = resolve_breakglass_signing_secret_with_source(
        settings, db=db
    )
    breakglass_secret = build_breakglass_secret_status(
        settings,
        db,
        effective_secret=bg_secret,
        effective_source=bg_source,
    )
    policy = get_or_create_policy(db)
    rules = {r.rule_type: r for r in list_ban_rules(db)}
    container_logs = ensure_container_logs_settings(db)
    siem_settings = ensure_siem_settings(db)
    return render(
        "admin/security.html",
        **_ctx(
            request,
            settings,
            subdomain_sso_enabled=get_subdomain_sso_enabled(db, settings),
            subdomain_apps=subdomain_apps,
            vault_key=vault_status,
            db_encryption=db_encryption,
            hot_store=hot_store,
            breakglass_secret=breakglass_secret.to_public_dict(),
            security_policy=policy,
            security_ban_rules=rules,
            security_bans=list_active_bans(db),
            security_allowlist=list_allowlist(db),
            container_logs_settings=container_logs,
            siem_settings=siem_settings,
            siem_status=siem_public_status(db),
        ),
    )


def _hot_store_flash(response, message: str, level: str, settings: Settings):
    flash_redirect(
        response,
        message,
        level,
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.post("/admin/security/hot-store/config")
def admin_security_hot_store_config(
    request: Request,
    host: str = Form(""),
    port: int = Form(5432),
    database: str = Form("bastion_hot"),
    user: str = Form("bastion_hot"),
    password: str = Form(""),
    sslmode: str = Form("prefer"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    admin=Depends(require_admin),
):
    from app.db.hot_store import HotStoreError
    from app.db.hot_store_service import save_hot_store_config

    response = RedirectResponse(url="/admin/security#hot-store", status_code=302)
    try:
        save_hot_store_config(
            db,
            settings,
            host=host,
            port=port,
            database=database,
            user=user,
            password=password,
            sslmode=sslmode,
            actor=admin.email or admin.username or "admin",
            ip_address=_client_ip(request),
        )
        return _hot_store_flash(response, "Connexion PostgreSQL enregistrée.", "success", settings)
    except HotStoreError as exc:
        return _hot_store_flash(response, str(exc), "error", settings)


@admin_router.post("/admin/security/hot-store/test")
def admin_security_hot_store_test(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _admin=Depends(require_admin),
):
    from app.db.hot_store import HotStoreError
    from app.db.hot_store_service import test_hot_store_config

    response = RedirectResponse(url="/admin/security#hot-store", status_code=302)
    try:
        result = test_hot_store_config(db, settings)
        msg = f"Connexion OK — {result.get('version', '')[:80]}"
        if result.get("can_create"):
            msg += " (CREATE OK)"
        return _hot_store_flash(response, msg, "success", settings)
    except HotStoreError as exc:
        return _hot_store_flash(response, str(exc), "error", settings)
    except Exception as exc:
        return _hot_store_flash(response, f"Échec : {exc}", "error", settings)


@admin_router.post("/admin/security/hot-store/prepare")
def admin_security_hot_store_prepare(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    admin=Depends(require_admin),
):
    from app.db.hot_store import HotStoreError
    from app.db.hot_store_service import prepare_hot_store_schema
    from app.audit import log_action

    response = RedirectResponse(url="/admin/security#hot-store", status_code=302)
    try:
        prepare_hot_store_schema(db, settings)
        log_action(
            db,
            actor=admin.email or admin.username or "admin",
            action="hot_store.schema_prepared",
            target="portal_settings",
            ip_address=_client_ip(request),
        )
        return _hot_store_flash(response, "Schéma hot store créé / à jour.", "success", settings)
    except HotStoreError as exc:
        return _hot_store_flash(response, str(exc), "error", settings)
    except Exception as exc:
        return _hot_store_flash(response, f"Échec schéma : {exc}", "error", settings)


@admin_router.post("/admin/security/hot-store/migrate")
def admin_security_hot_store_migrate(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    admin=Depends(require_admin),
):
    from app.db.hot_store import HotStoreError
    from app.db.hot_store_service import run_hot_store_migrate

    response = RedirectResponse(url="/admin/security#hot-store", status_code=302)
    try:
        counts = run_hot_store_migrate(
            db,
            settings,
            actor=admin.email or admin.username or "admin",
            ip_address=_client_ip(request),
        )
        total = sum(counts.values())
        return _hot_store_flash(
            response,
            f"Migration terminée — {total} ligne(s) copiée(s).",
            "success",
            settings,
        )
    except HotStoreError as exc:
        return _hot_store_flash(response, str(exc), "error", settings)
    except Exception as exc:
        return _hot_store_flash(response, f"Échec migration : {exc}", "error", settings)


@admin_router.post("/admin/security/hot-store/enable")
def admin_security_hot_store_enable(
    request: Request,
    enabled: str = Form("0"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    admin=Depends(require_admin),
):
    from app.db.hot_store import HotStoreError
    from app.db.hot_store_service import set_hot_store_enabled

    response = RedirectResponse(url="/admin/security#hot-store", status_code=302)
    want = str(enabled).strip().lower() in ("1", "true", "on", "yes")
    try:
        set_hot_store_enabled(
            db,
            settings,
            want,
            actor=admin.email or admin.username or "admin",
            ip_address=_client_ip(request),
        )
        msg = "Hot store activé." if want else "Hot store désactivé (retour SQLite)."
        return _hot_store_flash(response, msg, "success", settings)
    except HotStoreError as exc:
        return _hot_store_flash(response, str(exc), "error", settings)


@admin_router.post("/admin/security/container-logs")
def admin_security_container_logs(
    request: Request,
    enabled: str | None = Form(None),
    proxy_url: str = Form(""),
    tail_lines: int = Form(200),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.web.container_logs_settings import update_container_logs_settings

    update_container_logs_settings(
        db,
        enabled=enabled == "on",
        proxy_url=proxy_url,
        tail_lines=tail_lines,
        actor=user.email or user.username or "admin",
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url="/admin/security#container-logs", status_code=302)
    flash_redirect(
        response,
        "Paramètres logs containers enregistrés.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.post("/admin/security/container-logs/containers/add")
def admin_security_container_logs_add(
    request: Request,
    name: str = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.web.container_logs_settings import add_allowed_container

    try:
        add_allowed_container(
            db,
            name,
            actor=user.email or user.username or "admin",
            ip_address=_client_ip(request),
        )
        msg, kind = "Container ajouté à la liste blanche.", "success"
    except ValueError:
        msg, kind = "Nom de container invalide.", "error"
    response = RedirectResponse(url="/admin/security#container-logs", status_code=302)
    flash_redirect(
        response,
        msg,
        kind,
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.post("/admin/security/container-logs/containers/remove")
def admin_security_container_logs_remove(
    request: Request,
    name: str = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.web.container_logs_settings import remove_allowed_container

    remove_allowed_container(
        db,
        name,
        actor=user.email or user.username or "admin",
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url="/admin/security#container-logs", status_code=302)
    flash_redirect(
        response,
        "Container retiré de la liste blanche.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.post("/admin/security/siem")
def admin_security_siem(
    request: Request,
    enabled: str | None = Form(None),
    protocol: str = Form("webhook_https"),
    syslog_host: str = Form(""),
    syslog_port: int = Form(6514),
    syslog_tls_verify: str | None = Form(None),
    webhook_url: str = Form(""),
    webhook_auth_type: str = Form("none"),
    webhook_auth_secret: str = Form(""),
    clear_webhook_secret: str | None = Form(None),
    filter_mode: str = Form("denylist"),
    filter_actions: str = Form(""),
    retry_max_queue_size: int = Form(5000),
    retry_max_age_minutes: int = Form(1440),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.siem.settings_service import update_siem_settings

    actions = [a.strip() for a in (filter_actions or "").replace(";", ",").split(",") if a.strip()]
    try:
        update_siem_settings(
            db,
            settings,
            enabled=enabled == "on",
            protocol=protocol,
            syslog_host=syslog_host,
            syslog_port=syslog_port,
            syslog_tls_verify=syslog_tls_verify == "on",
            webhook_url=webhook_url,
            webhook_auth_type=webhook_auth_type,
            webhook_auth_secret=webhook_auth_secret or None,
            clear_webhook_secret=clear_webhook_secret == "on",
            filter_mode=filter_mode,
            filter_actions=actions,
            retry_max_queue_size=retry_max_queue_size,
            retry_max_age_minutes=retry_max_age_minutes,
            actor=user.email or user.username or "admin",
            ip_address=_client_ip(request),
        )
    except ValueError as exc:
        response = RedirectResponse(url="/admin/security#siem", status_code=302)
        flash_redirect(
            response,
            str(exc),
            "error",
            settings.vault_portal_internal_token or "dev",
        )
        return response
    response = RedirectResponse(url="/admin/security#siem", status_code=302)
    flash_redirect(
        response,
        "Paramètres SIEM enregistrés.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.post("/admin/security/siem/test")
def admin_security_siem_test(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.siem.outbox import run_connectivity_test

    ok, message = run_connectivity_test(
        db,
        settings,
        actor=user.email or user.username or "admin",
    )
    response = RedirectResponse(url="/admin/security#siem", status_code=302)
    flash_redirect(
        response,
        message,
        "success" if ok else "error",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.post("/admin/security/misc")
def admin_security_misc(
    request: Request,
    enabled: str | None = Form(None),
    breakglass_allow_cidrs: str = Form(""),
    breakglass_deny_cidrs: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.security.banning.service import update_policy_misc

    update_policy_misc(
        db,
        enabled=enabled == "on",
        breakglass_allow_cidrs=breakglass_allow_cidrs,
        breakglass_deny_cidrs=breakglass_deny_cidrs,
        actor=user.email or user.username or "admin",
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url="/admin/security#misc", status_code=302)
    flash_redirect(
        response,
        "Paramètres Misc enregistrés.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.post("/admin/security/banning/rules")
def admin_security_banning_rules(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    # hammering
    hammering_enabled: str | None = Form(None),
    hammering_threshold: int = Form(100),
    hammering_window_seconds: int = Form(100),
    hammering_ban_minutes: int = Form(60),
    hammering_ban_permanent: str | None = Form(None),
    hammering_confirm_permanent: str | None = Form(None),
    # hammering_login (login-path only)
    hammering_login_enabled: str | None = Form(None),
    hammering_login_threshold: int = Form(30),
    hammering_login_window_seconds: int = Form(60),
    hammering_login_ban_minutes: int = Form(60),
    hammering_login_ban_permanent: str | None = Form(None),
    hammering_login_confirm_permanent: str | None = Form(None),
    # failed_login
    failed_login_enabled: str | None = Form(None),
    failed_login_threshold: int = Form(15),
    failed_login_window_seconds: int = Form(300),
    failed_login_ban_minutes: int = Form(30),
    failed_login_ban_permanent: str | None = Form(None),
    failed_login_confirm_permanent: str | None = Form(None),
    failed_login_ban_username: str | None = Form(None),
    # successful_login
    successful_login_enabled: str | None = Form(None),
    successful_login_threshold: int = Form(20),
    successful_login_window_seconds: int = Form(300),
    successful_login_ban_minutes: int = Form(30),
    successful_login_ban_permanent: str | None = Form(None),
    successful_login_confirm_permanent: str | None = Form(None),
    # hack_username
    hack_username_enabled: str | None = Form(None),
    hack_usernames: str = Form("administrator,root"),
    hack_ban_minutes: int = Form(1440),
    hack_ban_permanent: str | None = Form(None),
    hack_confirm_permanent: str | None = Form(None),
    # concurrent
    concurrent_enabled: str | None = Form(None),
    concurrent_threshold: int = Form(0),
    # rate limit (throttle 429, no ban)
    rate_limit_enabled: str | None = Form(None),
    rate_limit_threshold: int = Form(120),
    rate_limit_window_seconds: int = Form(60),
    # rate limit login-only
    rate_limit_login_enabled: str | None = Form(None),
    rate_limit_login_threshold: int = Form(20),
    rate_limit_login_window_seconds: int = Form(60),
):
    from app.security.banning.service import update_ban_rules

    update_ban_rules(
        db,
        rules={
            "hammering": {
                "enabled": hammering_enabled == "on",
                "threshold": hammering_threshold,
                "window_seconds": hammering_window_seconds,
                "ban_minutes": hammering_ban_minutes,
                "ban_permanent": hammering_ban_permanent == "on",
                "confirm_permanent": hammering_confirm_permanent == "on",
            },
            "hammering_login": {
                "enabled": hammering_login_enabled == "on",
                "threshold": hammering_login_threshold,
                "window_seconds": hammering_login_window_seconds,
                "ban_minutes": hammering_login_ban_minutes,
                "ban_permanent": hammering_login_ban_permanent == "on",
                "confirm_permanent": hammering_login_confirm_permanent == "on",
            },
            "failed_login": {
                "enabled": failed_login_enabled == "on",
                "threshold": failed_login_threshold,
                "window_seconds": failed_login_window_seconds,
                "ban_minutes": failed_login_ban_minutes,
                "ban_permanent": failed_login_ban_permanent == "on",
                "confirm_permanent": failed_login_confirm_permanent == "on",
                "ban_username": failed_login_ban_username == "on",
            },
            "successful_login": {
                "enabled": successful_login_enabled == "on",
                "threshold": successful_login_threshold,
                "window_seconds": successful_login_window_seconds,
                "ban_minutes": successful_login_ban_minutes,
                "ban_permanent": successful_login_ban_permanent == "on",
                "confirm_permanent": successful_login_confirm_permanent == "on",
            },
            "hack_username": {
                "enabled": hack_username_enabled == "on",
                "usernames": hack_usernames,
                "ban_minutes": hack_ban_minutes,
                "ban_permanent": hack_ban_permanent == "on",
                "confirm_permanent": hack_confirm_permanent == "on",
            },
            "concurrent_connections": {
                "enabled": concurrent_enabled == "on",
                "threshold": concurrent_threshold,
            },
            "rate_limit": {
                "enabled": rate_limit_enabled == "on",
                "threshold": rate_limit_threshold,
                "window_seconds": rate_limit_window_seconds,
            },
            "rate_limit_login": {
                "enabled": rate_limit_login_enabled == "on",
                "threshold": rate_limit_login_threshold,
                "window_seconds": rate_limit_login_window_seconds,
            },
        },
        actor=user.email or user.username or "admin",
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url="/admin/security#banning", status_code=302)
    flash_redirect(
        response,
        "Règles anti-abus enregistrées.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.post("/admin/security/banning/add")
def admin_security_banning_add(
    request: Request,
    target_type: str = Form(...),
    target: str = Form(...),
    reason: str = Form(""),
    ban_mode: str = Form("temporary"),
    ban_minutes: int = Form(60),
    confirm_permanent: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.security.banning.service import apply_manual_ban

    permanent = ban_mode == "permanent"
    ban = apply_manual_ban(
        db,
        target_type=target_type,
        target=target,
        reason=reason,
        permanent=permanent,
        ban_minutes=ban_minutes,
        confirm_permanent=confirm_permanent == "on",
        actor=user.email or user.username or "admin",
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url="/admin/security#banning", status_code=302)
    if ban is None and permanent and confirm_permanent != "on":
        flash_redirect(
            response,
            "Ban permanent refusé : cochez la confirmation explicite.",
            "error",
            settings.vault_portal_internal_token or "dev",
        )
    elif ban is None:
        flash_redirect(
            response,
            "Ban non appliqué (cible en liste blanche ou déjà bannie).",
            "error",
            settings.vault_portal_internal_token or "dev",
        )
    else:
        flash_redirect(
            response,
            "Ban ajouté.",
            "success",
            settings.vault_portal_internal_token or "dev",
        )
    return response


@admin_router.post("/admin/security/banning/lift/{ban_id}")
def admin_security_banning_lift(
    ban_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.security.banning.service import lift_ban

    lift_ban(
        db,
        ban_id,
        actor=user.email or user.username or "admin",
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url="/admin/security#banning", status_code=302)
    flash_redirect(
        response,
        "Ban levé.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.post("/admin/security/allowlist/add")
def admin_security_allowlist_add(
    request: Request,
    entry_type: str = Form(...),
    value: str = Form(...),
    comment: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.security.banning.service import add_allowlist_entry

    try:
        add_allowlist_entry(
            db,
            entry_type=entry_type,
            value=value,
            comment=comment,
            actor=user.email or user.username or "admin",
            ip_address=_client_ip(request),
        )
        msg, level = "Entrée ajoutée à la liste blanche.", "success"
    except ValueError as exc:
        msg, level = str(exc), "error"
    response = RedirectResponse(url="/admin/security#banning", status_code=302)
    flash_redirect(
        response,
        msg,
        level,
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.post("/admin/security/allowlist/remove/{entry_id}")
def admin_security_allowlist_remove(
    entry_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.security.banning.service import remove_allowlist_entry

    remove_allowlist_entry(
        db,
        entry_id,
        actor=user.email or user.username or "admin",
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url="/admin/security#banning", status_code=302)
    flash_redirect(
        response,
        "Entrée retirée de la liste blanche.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.post("/admin/security/breakglass-jwt-secret/generate")
def admin_security_breakglass_jwt_secret_generate(
    request: Request,
    confirm: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.breakglass_secret_service import (
        env_breakglass_secret_defined,
        generate_or_rotate_ui_breakglass_secret,
    )

    token = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/admin/security#breakglass-jwt", status_code=302)
    if env_breakglass_secret_defined(settings):
        flash_redirect(
            response,
            "Secret déjà défini via BREAKGLASS_JWT_SECRET (AWX) — génération UI désactivée.",
            "error",
            token,
        )
        return response
    if confirm != "on":
        flash_redirect(
            response,
            "Génération annulée : confirmation requise.",
            "error",
            token,
        )
        return response
    actor = user.email or user.username or "admin"
    ip = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    try:
        generate_or_rotate_ui_breakglass_secret(
            db, settings, actor=actor, ip_address=ip
        )
    except PermissionError as exc:
        flash_redirect(response, str(exc), "error", token)
        return response
    except ValueError as exc:
        flash_redirect(response, str(exc), "error", token)
        return response

    from app.breakglass_secret_service import get_ui_breakglass_previous_secret

    if get_ui_breakglass_previous_secret(db, settings):
        msg = (
            "Secret break-glass régénéré (rotation). Les cookies déjà émis restent "
            "valides pendant la transition."
        )
    else:
        msg = "Secret break-glass dédié généré et actif."
    flash_redirect(response, msg, "success", token)
    return response


@admin_router.get("/admin/security/vault-key")
def admin_security_vault_key_redirect():
    return RedirectResponse(url="/admin/security#vault", status_code=302)


@admin_router.post("/admin/security/vault-key/rotate")
def admin_security_vault_key_rotate(
    request: Request,
    confirm: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.vault.key_rotation_service import KeyRotationError, rotate_application_key

    token = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/admin/security#vault", status_code=302)
    if confirm != "on":
        flash_redirect(
            response,
            "Rotation annulée : confirmation requise.",
            "error",
            token,
        )
        return response
    actor = user.email or user.username or "admin"
    ip = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    try:
        report = rotate_application_key(
            db, settings, actor=actor, ip_address=ip
        )
        flash_redirect(
            response,
            f"Clé Fernet renouvelée (version active). {report.total} secret(s) ré-chiffré(s).",
            "success",
            token,
        )
    except KeyRotationError:
        flash_redirect(
            response,
            "Échec de la rotation — base inchangée (rollback). Voir les logs admin.",
            "error",
            token,
        )
    return response


@admin_router.post("/admin/security/vault-key/cadence")
def admin_security_vault_key_cadence(
    request: Request,
    rotation_days: int = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.portal_settings_service import set_vault_key_rotation_days

    token = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/admin/security#vault", status_code=302)
    days = max(1, min(3650, int(rotation_days)))
    set_vault_key_rotation_days(
        db,
        settings,
        days,
        actor=user.email or user.username or "admin",
        ip_address=request.headers.get("X-Real-IP")
        or (request.client.host if request.client else None),
    )
    flash_redirect(
        response,
        f"Cadence de rotation enregistrée : {days} jours (aucune rotation automatique).",
        "success",
        token,
    )
    return response


@admin_router.post("/admin/security/vault-key/export")
def admin_security_vault_key_export(
    passphrase: str = Form(...),
    passphrase_confirm: str = Form(...),
    settings: Settings = Depends(get_settings),
):
    from fastapi.responses import Response

    from app.vault.encryption_key_store import (
        EncryptionKeyStoreError,
        export_active_key_backup,
        get_active_version,
    )

    if passphrase != passphrase_confirm:
        response = RedirectResponse(url="/admin/security#vault", status_code=302)
        flash_redirect(
            response,
            "Export annulé : les passphrases ne correspondent pas.",
            "error",
            settings.vault_portal_internal_token or "dev",
        )
        return response
    try:
        payload = export_active_key_backup(settings, passphrase)
    except EncryptionKeyStoreError as exc:
        response = RedirectResponse(url="/admin/security#vault", status_code=302)
        flash_redirect(
            response,
            str(exc),
            "error",
            settings.vault_portal_internal_token or "dev",
        )
        return response
    version = get_active_version() or 0
    return Response(
        content=payload,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": (
                f'attachment; filename="bastion-fernet-v{version}.backup"'
            ),
        },
    )


@admin_router.post("/admin/security/subdomain-sso")
def admin_security_subdomain_sso(
    request: Request,
    enabled: str | None = Form(None),
    infra_ack: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    from app.portal_settings_service import set_subdomain_sso_enabled

    want_enabled = enabled == "on"
    if want_enabled and infra_ack != "on":
        response = RedirectResponse(url="/admin/security#subdomain-sso", status_code=302)
        flash_redirect(
            response,
            "Activation refusée : confirmez d'abord que l'infrastructure sous-domaine est prête.",
            "error",
            settings.vault_portal_internal_token or "dev",
        )
        return response

    set_subdomain_sso_enabled(
        db,
        settings,
        want_enabled,
        actor=user.email or user.username or "admin",
        ip_address=request.headers.get("X-Real-IP")
        or (request.client.host if request.client else None),
    )
    response = RedirectResponse(url="/admin/security#subdomain-sso", status_code=302)
    flash_redirect(
        response,
        "Routage par sous-domaine "
        + ("activé." if want_enabled else "désactivé."),
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@admin_router.get("/admin/health")
def admin_health(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    apps = db.query(App).filter_by(enabled=True).order_by(App.label).all()
    probes = [probe_row_from_app(app) for app in apps]
    status_counts = compute_status_counts(probes)
    total = len(probes)
    health_score = compute_health_score(status_counts, total)
    return render(
        "admin/health.html",
        **_ctx(
            request,
            settings,
            probes=probes,
            status_counts=status_counts,
            health_score=health_score,
        ),
    )
