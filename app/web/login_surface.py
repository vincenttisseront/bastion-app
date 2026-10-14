"""Login page surface: realm chooser, native vs oauth2-proxy SSO, break-glass gate.

Shared by the HTML login routes and the OIDC BFF error re-render.
"""

from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth.flow import get_default_idp_realm, oauth2_start_url
from app.models import RealmConfig
from app.request_client_ip import client_ip_from_request, client_ip_probe
from app.sso_settings import Settings


def is_breakglass_lan_allowed(
    request: Request, db: Session, settings: Settings
) -> bool:
    """True only for LAN / allowlisted clients — never expose BG paths on the public Internet."""
    from app.security.banning.engine import is_breakglass_ip_allowed

    return is_breakglass_ip_allowed(
        db, client_ip_from_request(request), rfc1918_cidrs=settings.rfc1918_cidrs
    )


def log_breakglass_ip_denied(
    db: Session,
    request: Request,
    *,
    actor: str,
    via: str,
) -> None:
    client_ip = client_ip_from_request(request)
    probe = client_ip_probe(request)
    log_action(
        db,
        actor=actor,
        action="breakglass.login_denied_non_lan",
        details={
            "reason": "breakglass_ip_not_allowed",
            "via": via,
            "resolved": client_ip or None,
            "x_real_ip": probe.get("x_real_ip"),
            "x_forwarded_for": probe.get("x_forwarded_for"),
            "peer": probe.get("request_client_host"),
        },
        ip_address=client_ip or None,
    )


def login_audience_label(realm: RealmConfig) -> str:
    """Short audience label for the login chooser (Interne / Clients / name)."""
    custom = (getattr(realm, "login_label", None) or "").strip()
    if custom:
        return custom
    blob = f"{realm.slug or ''} {realm.name or ''}".lower()
    if any(token in blob for token in ("client", "externe", "customer")):
        return "Clients"
    if any(token in blob for token in ("interne", "internal", "staff")):
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


def _ordered_enabled_realms(
    db: Session, default: RealmConfig | None
) -> list[RealmConfig]:
    enabled_rows = (
        db.query(RealmConfig)
        .filter(RealmConfig.enabled.is_(True))
        .order_by(RealmConfig.slug.asc())
        .all()
    )
    ordered: list[RealmConfig] = []
    if default is not None:
        ordered.append(default)
    for row in enabled_rows:
        if default is None or row.id != default.id:
            ordered.append(row)
    return ordered


def _select_login_realm(
    login_realms: list[RealmConfig], *, want: str
) -> RealmConfig | None:
    if want:
        for row in login_realms:
            if (row.slug or "").lower() == want:
                return row
    if login_realms:
        return login_realms[0]
    return None


def _native_realm_option_dicts(
    db: Session,
    settings: Settings,
    login_realms: list[RealmConfig],
    *,
    is_native,
) -> list[dict]:
    return [
        {
            "slug": row.slug,
            "name": row.name,
            "label": login_audience_label(row),
            "native": is_native(db, row.slug, settings),
            "mfa": bool(getattr(row, "oidc_mfa_enabled", True)),
        }
        for row in login_realms
    ]


def login_surface_flags(
    request: Request,
    db: Session,
    settings: Settings,
    *,
    rd: str,
    preferred_realm: str | None = None,
) -> dict:
    """Shared flags for auth/login.html (native SSO vs oauth2-proxy vs break-glass)."""
    from app.auth.oidc_native_session import is_oidc_native_session_enabled_for_realm
    from app.rbac.access_request_service import realms_advertising_access_requests

    default = get_default_idp_realm(db)
    ordered = _ordered_enabled_realms(db, default)
    login_realms = [row for row in ordered if _realm_is_login_ready(row)]
    want = (preferred_realm or request.query_params.get("realm") or "").strip().lower()
    selected = _select_login_realm(login_realms, want=want)

    selected_native = bool(
        selected
        and is_oidc_native_session_enabled_for_realm(db, selected.slug, settings)
    )
    oauth2_url = (
        oauth2_start_url(selected.slug, rd)
        if selected is not None and not selected_native
        else None
    )
    native_realm_options = _native_realm_option_dicts(
        db,
        settings,
        login_realms,
        is_native=is_oidc_native_session_enabled_for_realm,
    )
    return {
        "show_native_login": selected_native,
        "native_realm_slug": selected.slug if selected else None,
        "native_realm_name": selected.name if selected else None,
        "native_realm_label": (
            login_audience_label(selected) if selected else None
        ),
        "native_realm_options": native_realm_options,
        "show_realm_chooser": len(native_realm_options) > 1,
        "oauth2_url": oauth2_url,
        "show_breakglass": is_breakglass_lan_allowed(request, db, settings),
        "show_access_request": bool(realms_advertising_access_requests(db)),
        "rd": rd,
    }
