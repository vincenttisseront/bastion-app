"""Admin actions on ActiveSync devices (user fiche section).

Blocking is deliberately effective before the per-app device gate is switched
on: a stolen phone must be cuttable the day it is reported, not the day the
rollout completes.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    ACTIVESYNC_DEVICE_APPROVED,
    ACTIVESYNC_DEVICE_BLOCKED,
    ACTIVESYNC_DEVICE_PENDING,
    ACTIVESYNC_DEVICE_REJECTED,
    ActiveSyncDevice,
    App,
)
from app.sso_settings import Settings, get_settings
from app.subdomain import activesync_device_service as device_service
from app.subdomain.activesync_device_service import DeviceDecisionError
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context, flash_redirect
from app.web.templates import render
from app.web.user_context import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-activesync-devices"])

_STATUS_BADGES: dict[str, tuple[str, str]] = {
    ACTIVESYNC_DEVICE_APPROVED: ("badge-ok", "Approuvé"),
    ACTIVESYNC_DEVICE_PENDING: ("badge-warn", "En attente"),
    ACTIVESYNC_DEVICE_REJECTED: ("badge-warn", "Refusé"),
    ACTIVESYNC_DEVICE_BLOCKED: ("badge-danger", "Bloqué"),
}

_SOURCE_LABELS: dict[str, str] = {
    "observed": "observé",
    "backfill": "hérité (backfill)",
    "user": "utilisateur",
    "admin": "admin",
}


def shorten_device_id(device_id: str) -> str:
    """8 first + 4 last chars — EAS ids are long and unreadable in a table."""
    raw = (device_id or "").strip()
    if len(raw) <= 14:
        return raw
    return f"{raw[:8]}…{raw[-4:]}"


def activesync_enabled_apps(db: Session) -> list[App]:
    return (
        db.query(App)
        .filter(App.allow_activesync.is_(True))
        .order_by(App.label.asc())
        .all()
    )


def serialize_device(device: ActiveSyncDevice, app: App | None) -> dict:
    from app.subdomain.eas_device_identity import describe_eas_device

    badge_class, badge_label = _STATUS_BADGES.get(
        device.status, ("badge", device.status)
    )
    # Pending means "seen, undecided" while the gate is off — not "user must act".
    control_on = bool(app and getattr(app, "activesync_device_control", False))
    if device.status == ACTIVESYNC_DEVICE_PENDING:
        if control_on:
            badge_class, badge_label = ("badge-warn", "En attente de validation")
        else:
            badge_class, badge_label = ("badge", "Inventorié")
    identity = describe_eas_device(
        device_id=device.device_id,
        device_type=device.device_type,
        user_agent=device.user_agent,
        client_kind=device.client_kind,
        friendly_name=device.friendly_name,
    )
    return {
        "id": device.id,
        "device_id": device.device_id,
        "device_id_short": shorten_device_id(device.device_id),
        "friendly_name": device.friendly_name,
        "display_name": identity["display_name"]
        or device.friendly_name
        or shorten_device_id(device.device_id),
        "apple_serial": identity["apple_serial"],
        "model_label": identity["model_label"],
        "ua_summary": identity["ua_summary"],
        "identity_line": identity["identity_line"],
        "client_kind_label": identity["client_kind_label"],
        "device_type": device.device_type,
        "client_kind": device.client_kind,
        "user_agent": device.user_agent,
        "user_key": device.user_key,
        "app_slug": app.slug if app else None,
        "app_label": app.label if app else None,
        "app_fqdn": app.public_fqdn if app else None,
        "app_device_control": control_on,
        "status": device.status,
        "status_badge_class": badge_class,
        "status_label": badge_label,
        "source": device.source,
        "source_label": _SOURCE_LABELS.get(device.source, device.source),
        "blocked_by_admin": bool(device.blocked_by_admin),
        "first_seen_at": device.first_seen_at,
        "last_seen_at": device.last_seen_at,
        "request_count": device.request_count,
        "last_ip": device.last_ip,
        "decided_by": device.decided_by,
        "decided_at": device.decided_at,
        "decision_note": device.decision_note,
    }


def build_user_devices_context(
    db: Session,
    *,
    user_keys: list[str],
    keycloak_user_id: str | None,
    realm_id: int | None,
) -> dict:
    """Devices of one person for the admin fiche.

    Matches on the EAS identity (``user_key``) as well as the Keycloak id, and
    opportunistically stores the link — this is the one place that knows both,
    and doing it here keeps any directory lookup out of the auth hot path.
    """
    eas_apps = activesync_enabled_apps(db)
    if not eas_apps:
        return {"activesync_available": False, "activesync_devices": []}

    devices = device_service.devices_for_identities(
        db, user_keys=user_keys, keycloak_user_id=keycloak_user_id
    )
    devices = device_service.repair_domain_prefixed_user_keys(db, devices)
    device_service.link_devices_to_keycloak_user(
        db, devices=devices, keycloak_user_id=keycloak_user_id, realm_id=realm_id
    )
    apps_by_id = {a.id: a for a in db.query(App).all()}
    return {
        "activesync_available": True,
        "activesync_devices": [
            serialize_device(d, apps_by_id.get(d.application_id)) for d in devices
        ],
    }


def _device_or_404(db: Session, device_id: int) -> ActiveSyncDevice:
    device = db.get(ActiveSyncDevice, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Appareil introuvable")
    return device


def _safe_redirect_url(raw: str | None, fallback: str) -> str:
    """Only allow same-origin relative admin paths (open-redirect guard)."""
    value = (raw or "").strip()
    if value.startswith("/admin/") and "://" not in value and "\\" not in value:
        return value
    return fallback


def _actor(user) -> str:
    return getattr(user, "email", None) or getattr(user, "username", None) or "admin"


def _fmt_short_dt(value) -> str:
    if value is None:
        return "—"
    try:
        return value.strftime("%d/%m %H:%M")
    except Exception:
        return str(value)[:16]


def _inventory_seen_key(row: dict):
    """Sort key that never mixes datetime with 0 (TypeError on Py3)."""
    from datetime import datetime, timezone

    seen = row.get("first_seen_at")
    if seen is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if getattr(seen, "tzinfo", None) is None:
        return seen.replace(tzinfo=timezone.utc)
    return seen


def _drawer_payload(row: dict) -> dict:
    """JSON-safe fields for the right-hand detail drawer."""
    return {
        "id": row.get("id"),
        "user_key": row.get("user_key"),
        "display_name": row.get("display_name"),
        "device_id": row.get("device_id"),
        "device_id_short": row.get("device_id_short"),
        "apple_serial": row.get("apple_serial"),
        "model_label": row.get("model_label"),
        "identity_line": row.get("identity_line"),
        "ua_summary": row.get("ua_summary"),
        "user_agent": row.get("user_agent"),
        "device_type": row.get("device_type"),
        "client_kind_label": row.get("client_kind_label"),
        "app_label": row.get("app_label"),
        "app_slug": row.get("app_slug"),
        "app_fqdn": row.get("app_fqdn"),
        "status": row.get("status"),
        "status_label": row.get("status_label"),
        "status_badge_class": row.get("status_badge_class"),
        "source_label": row.get("source_label"),
        "request_count": row.get("request_count"),
        "first_seen_at": str(row.get("first_seen_at") or "—"),
        "last_seen_at": str(row.get("last_seen_at") or "—"),
        "last_ip": row.get("last_ip"),
        "decided_by": row.get("decided_by"),
        "decided_at": str(row.get("decided_at") or "") or None,
        "decision_note": row.get("decision_note"),
        "fiche_url": row.get("fiche_url"),
        "blocked_by_admin": bool(row.get("blocked_by_admin")),
    }


@router.get("/admin/pending-devices")
def admin_pending_devices_list(
    request: Request,
    status: str = Query("pending"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    """Queue of ActiveSync devices — same pending-items pattern as domaines / users."""
    status_filter = (status or "pending").strip().lower()
    # Drop DOMAIN\email twins so an already-approved phone leaves the queue.
    device_service.reconcile_duplicate_devices(db)
    query = db.query(ActiveSyncDevice)
    if status_filter != "all":
        query = query.filter(ActiveSyncDevice.status == status_filter)
    devices = query.order_by(ActiveSyncDevice.last_seen_at.desc()).limit(500).all()
    apps_by_id = {a.id: a for a in db.query(App).all()}
    rows = []
    for device in devices:
        row = serialize_device(device, apps_by_id.get(device.application_id))
        if device.keycloak_user_id and device.realm_id:
            row["fiche_url"] = (
                f"/admin/rbac/users/view?realm_id={device.realm_id}"
                f"&keycloak_user_id={device.keycloak_user_id}#appareils"
            )
        else:
            row["fiche_url"] = None
        row["first_seen_label"] = _fmt_short_dt(device.first_seen_at)
        row["last_seen_label"] = _fmt_short_dt(device.last_seen_at)
        row["drawer"] = _drawer_payload(row)
        rows.append(row)
    return render(
        "admin/pending_devices/list.html",
        **base_template_context(
            request,
            settings,
            APP_VERSION,
            rows=rows,
            status_filter=status_filter,
            list_redirect=f"/admin/pending-devices?status={status_filter}",
        ),
    )


@router.post("/admin/activesync/devices/{device_id}/block")
def admin_activesync_device_block(
    device_id: int,
    reason: str = Form(""),
    redirect_url: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    device = _device_or_404(db, device_id)
    secret = settings.vault_portal_internal_token or "dev"
    dest = _safe_redirect_url(redirect_url, "/admin/pending-devices?status=pending")
    response = RedirectResponse(url=dest, status_code=302)
    label = shorten_device_id(device.device_id)
    try:
        device_service.admin_block_device(db, device, actor=_actor(user), reason=reason)
    except DeviceDecisionError as exc:
        flash_redirect(response, str(exc), "error", secret)
        return response
    flash_redirect(
        response,
        f"Appareil {label} bloqué — l'utilisateur ne pourra pas le réactiver.",
        "success",
        secret,
    )
    return response


@router.post("/admin/activesync/devices/{device_id}/unblock")
def admin_activesync_device_unblock(
    device_id: int,
    redirect_url: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    device = _device_or_404(db, device_id)
    secret = settings.vault_portal_internal_token or "dev"
    dest = _safe_redirect_url(redirect_url, "/admin/pending-devices?status=pending")
    response = RedirectResponse(url=dest, status_code=302)
    label = shorten_device_id(device.device_id)
    device_service.admin_unblock_device(db, device, actor=_actor(user))
    flash_redirect(response, f"Appareil {label} débloqué (en attente).", "success", secret)
    return response


@router.post("/admin/activesync/devices/{device_id}/approve")
def admin_activesync_device_approve(
    device_id: int,
    redirect_url: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    device = _device_or_404(db, device_id)
    secret = settings.vault_portal_internal_token or "dev"
    dest = _safe_redirect_url(redirect_url, "/admin/pending-devices?status=pending")
    response = RedirectResponse(url=dest, status_code=302)
    label = shorten_device_id(device.device_id)
    device_service.admin_approve_device(db, device, actor=_actor(user))
    flash_redirect(response, f"Appareil {label} approuvé.", "success", secret)
    return response


def _app_or_404(db: Session, slug: str) -> App:
    app = db.query(App).filter(App.slug == slug).first()
    if app is None:
        raise HTTPException(status_code=404, detail="Application introuvable")
    return app


def _redirect_unless_activesync(app: App, settings: Settings) -> RedirectResponse | None:
    """Device-control UI exists only on apps that actually proxy EAS."""
    if app.allow_activesync:
        return None
    dest = f"/admin/apps/{app.slug}/edit"
    response = RedirectResponse(url=dest, status_code=302)
    flash_redirect(
        response,
        "Le contrôle des appareils n’est disponible que si ActiveSync est activé sur cette application.",
        "error",
        settings.vault_portal_internal_token or "dev",
    )
    return response


def _utcnow_days_since(when) -> int:
    from datetime import datetime, timezone

    if when is None:
        return 0
    now = datetime.now(timezone.utc)
    if getattr(when, "tzinfo", None) is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0, (now - when).days)


@router.get("/admin/apps/{slug}/activesync/devices/preview")
def admin_activesync_control_preview(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    """Simulate backfill + gate arming — does not change anything until confirm."""
    app = _app_or_404(db, slug)
    blocked = _redirect_unless_activesync(app, settings)
    if blocked is not None:
        return blocked
    preview = device_service.preview_device_control(db, app)
    inventory = []
    for device in (
        preview["pending"]
        + preview["approved"]
        + preview["blocked"]
        + preview["rejected"]
    ):
        row = serialize_device(device, app)
        row["first_seen_label"] = _fmt_short_dt(device.first_seen_at)
        inventory.append(row)
    inventory.sort(key=_inventory_seen_key)
    return render(
        "admin/activesync/control_preview.html",
        **base_template_context(
            request,
            settings,
            APP_VERSION,
            app=app,
            preview=preview,
            inventory=inventory,
            inventory_days=(
                _utcnow_days_since(preview["inventory_since"])
                if preview.get("inventory_since")
                else None
            ),
        ),
    )


@router.post("/admin/apps/{slug}/activesync/devices/enable")
def admin_activesync_control_enable(
    slug: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    app = _app_or_404(db, slug)
    blocked = _redirect_unless_activesync(app, settings)
    if blocked is not None:
        return blocked
    secret = settings.vault_portal_internal_token or "dev"
    dest = f"/admin/apps/{slug}/activesync/devices/preview"
    response = RedirectResponse(url=dest, status_code=302)
    try:
        result = device_service.enable_device_control(db, app, actor=_actor(user))
    except DeviceDecisionError as exc:
        flash_redirect(response, str(exc), "error", secret)
        return response
    flash_redirect(
        response,
        (
            f"Contrôle activé : {result['approved_from_pending']} appareil(s) "
            f"approuvé(s) depuis l'inventaire ({result['inventory_total']} au total)."
        ),
        "success",
        secret,
    )
    return response


@router.post("/admin/apps/{slug}/activesync/devices/disable")
def admin_activesync_control_disable(
    slug: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    app = _app_or_404(db, slug)
    blocked = _redirect_unless_activesync(app, settings)
    if blocked is not None:
        return blocked
    secret = settings.vault_portal_internal_token or "dev"
    dest = f"/admin/apps/{slug}/activesync/devices/preview"
    response = RedirectResponse(url=dest, status_code=302)
    device_service.disable_device_control(db, app, actor=_actor(user))
    flash_redirect(
        response,
        "Contrôle suspendu — inventaire et décisions conservés.",
        "success",
        secret,
    )
    return response
