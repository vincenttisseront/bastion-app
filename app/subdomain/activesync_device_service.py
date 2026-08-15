"""ActiveSync device inventory — sighting upserts and admin decisions.

An EAS client sends ``Cmd=Ping`` every 30 s or so, per device, forever. Writing
the sighting on every hit would hammer the SQLCipher config DB for no gain, so
the row is read on each request (the status must be authoritative — a
revocation has to bite immediately) but written at most once a minute per
device, with the skipped hits accumulated in memory so ``request_count`` stays
truthful.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone

from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import (
    ACTIVESYNC_DEVICE_APPROVED,
    ACTIVESYNC_DEVICE_BLOCKED,
    ACTIVESYNC_DEVICE_MAX_SAMPLE_IPS,
    ACTIVESYNC_DEVICE_PENDING,
    ActiveSyncDevice,
    App,
    RealmConfig,
)
from app.subdomain.eas_device import (
    explain_eas_device_miss,
    miss_family,
    path_of,
    query_sample,
    split_query,
)

logger = logging.getLogger(__name__)

SIGHTING_WRITE_INTERVAL_SEC = 60.0
UNIDENTIFIED_LOG_INTERVAL_SEC = 3600.0
DENIAL_LOG_INTERVAL_SEC = 3600.0

_lock = threading.Lock()
# (application_id, user_key, device_id) -> [last_write_monotonic, pending_hits, pending_ips]
_pending_sightings: dict[tuple[int, str, str], list] = {}
_unidentified_log_ts: dict[tuple[str, str], float] = {}
_denial_log_ts: dict[tuple[int, str], float] = {}

_CACHE_MAX_ENTRIES = 5000


def normalize_user_key(raw: str | None) -> str:
    """Basic Auth identity, lowercased. Empty when unusable."""
    return (raw or "").strip().lower()[:255]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _claim_sighting(
    key: tuple[int, str, str], client_ip: str | None
) -> tuple[bool, int, list[str]]:
    """Register a hit; return (should_write, hits_to_flush, ips_to_merge)."""
    now = time.monotonic()
    with _lock:
        if len(_pending_sightings) > _CACHE_MAX_ENTRIES:
            _pending_sightings.clear()
        entry = _pending_sightings.get(key)
        if entry is None:
            _pending_sightings[key] = [now, 0, []]
            return True, 1, [client_ip] if client_ip else []

        entry[1] += 1
        if client_ip and client_ip not in entry[2]:
            if len(entry[2]) < ACTIVESYNC_DEVICE_MAX_SAMPLE_IPS:
                entry[2].append(client_ip)
        if now - entry[0] < SIGHTING_WRITE_INTERVAL_SEC:
            return False, 0, []

        hits, ips = entry[1], entry[2]
        entry[0], entry[1], entry[2] = now, 0, []
        return True, hits, ips


def _forget_sighting(key: tuple[int, str, str]) -> None:
    with _lock:
        _pending_sightings.pop(key, None)


def reset_sighting_cache() -> None:
    """Drop the write-throttle state (tests, and after a bulk backfill)."""
    with _lock:
        _pending_sightings.clear()
        _unidentified_log_ts.clear()
        _denial_log_ts.clear()


def should_log_denial(application_id: int, device_id: str) -> bool:
    """First refusal is logged in clear, then at most one per device per hour.

    A denied phone retries every 30 s forever; without this the audit table is
    a single device's Ping loop.
    """
    key = (application_id, device_id)
    now = time.monotonic()
    with _lock:
        last = _denial_log_ts.get(key, 0.0)
        if last and now - last < DENIAL_LOG_INTERVAL_SEC:
            return False
        if len(_denial_log_ts) > _CACHE_MAX_ENTRIES:
            _denial_log_ts.clear()
        _denial_log_ts[key] = now
    return True


def should_log_unidentified(app_slug: str, user_agent: str) -> bool:
    key = (app_slug or "-", (user_agent or "-")[:120])
    now = time.monotonic()
    with _lock:
        last = _unidentified_log_ts.get(key, 0.0)
        if now - last < UNIDENTIFIED_LOG_INTERVAL_SEC:
            return False
        if len(_unidentified_log_ts) > _CACHE_MAX_ENTRIES:
            _unidentified_log_ts.clear()
        _unidentified_log_ts[key] = now
    return True


def get_device(
    db: Session, *, application_id: int, user_key: str, device_id: str
) -> ActiveSyncDevice | None:
    return (
        db.query(ActiveSyncDevice)
        .filter(
            ActiveSyncDevice.application_id == application_id,
            ActiveSyncDevice.user_key == user_key,
            ActiveSyncDevice.device_id == device_id,
        )
        .first()
    )


def _realm_id_for_app(db: Session, app: App) -> int | None:
    slug = (getattr(app, "realm_slug", None) or "").strip()
    if not slug:
        return None
    realm = db.query(RealmConfig).filter_by(slug=slug).first()
    return realm.id if realm else None


def record_sighting(
    db: Session,
    *,
    app: App,
    user_key: str,
    device_id: str,
    device_type: str | None = None,
    user_agent: str | None = None,
    client_kind: str | None = None,
    client_ip: str | None = None,
) -> ActiveSyncDevice | None:
    """Read (and throttled-write) the device row for this sighting.

    Returns the row so the caller can act on ``status``. Returns ``None`` only
    when the inventory could not be reached — never a reason to deny.
    """
    if not user_key or not device_id:
        return None

    key = (app.id, user_key, device_id)
    device = get_device(
        db, application_id=app.id, user_key=user_key, device_id=device_id
    )

    if device is None:
        _forget_sighting(key)
        return _create_device(
            db,
            app=app,
            user_key=user_key,
            device_id=device_id,
            device_type=device_type,
            user_agent=user_agent,
            client_kind=client_kind,
            client_ip=client_ip,
        )

    should_write, hits, ips = _claim_sighting(key, client_ip)
    if not should_write:
        return device

    try:
        device.last_seen_at = _utcnow()
        device.request_count = int(device.request_count or 0) + max(1, hits)
        if client_ip:
            device.last_ip = client_ip
        merged = list(device.sample_source_ips or [])
        for candidate in [*ips, client_ip]:
            if candidate and candidate not in merged:
                if len(merged) >= ACTIVESYNC_DEVICE_MAX_SAMPLE_IPS:
                    break
                merged.append(candidate)
        device.sample_source_ips = merged
        if device_type and device.device_type != device_type:
            device.device_type = device_type
        if user_agent:
            device.user_agent = user_agent[:512]
        if client_kind:
            device.client_kind = client_kind
        db.commit()
    except SQLAlchemyError:
        logger.exception("activesync sighting update failed device_id=%s", device_id)
        try:
            db.rollback()
        except SQLAlchemyError:
            logger.exception("activesync sighting rollback failed")
    return device


def _create_device(
    db: Session,
    *,
    app: App,
    user_key: str,
    device_id: str,
    device_type: str | None,
    user_agent: str | None,
    client_kind: str | None,
    client_ip: str | None,
) -> ActiveSyncDevice | None:
    now = _utcnow()
    device = ActiveSyncDevice(
        application_id=app.id,
        user_key=user_key,
        realm_id=_realm_id_for_app(db, app),
        device_id=device_id,
        device_type=device_type,
        user_agent=(user_agent or "")[:512] or None,
        client_kind=client_kind,
        status=ACTIVESYNC_DEVICE_PENDING,
        source="observed",
        first_seen_at=now,
        last_seen_at=now,
        request_count=1,
        last_ip=client_ip,
        sample_source_ips=[client_ip] if client_ip else [],
    )
    try:
        db.add(device)
        db.commit()
        db.refresh(device)
    except SQLAlchemyError:
        # Concurrent worker won the unique constraint — re-read, do not fail.
        try:
            db.rollback()
        except SQLAlchemyError:
            logger.exception("activesync device rollback failed")
        existing = get_device(
            db, application_id=app.id, user_key=user_key, device_id=device_id
        )
        if existing is None:
            logger.exception("activesync device insert failed device_id=%s", device_id)
        return existing

    log_action(
        db,
        actor=user_key,
        action="activesync.device_discovered",
        target=app.slug,
        details={
            "application_id": app.id,
            "device_id": device_id,
            "device_type": device_type,
            "client_kind": client_kind,
            "user_agent": (user_agent or "")[:512] or None,
            "status": device.status,
            "device_control": bool(app.activesync_device_control),
        },
        ip_address=client_ip,
    )
    return device


def log_unidentified_device(
    db: Session,
    *,
    app: App,
    actor: str,
    uri: str,
    user_agent: str | None,
    client_kind: str | None,
    client_ip: str | None,
) -> None:
    """Measure the identification hole (never a reason to deny).

    Carries a bounded sample of the raw query and the reason extraction gave
    up, so the MS-ASHTTP decoder can be fixed against real traffic before the
    per-device gate is armed — an unidentified device is currently let through.
    """
    if not should_log_unidentified(app.slug, user_agent or ""):
        return
    raw_query = split_query(uri or "")
    reason = explain_eas_device_miss(uri or "")
    log_action(
        db,
        actor=actor or "anonymous",
        action="activesync.device_unidentified",
        target=app.slug,
        details={
            "application_id": app.id,
            "path": path_of(uri or "/")[:256],
            "query_sample": query_sample(uri or ""),
            "query_len": len(raw_query),
            "miss_reason": reason,
            "miss_family": miss_family(reason),
            "user_agent": (user_agent or "")[:512] or None,
            "client_kind": client_kind,
        },
        ip_address=client_ip,
    )


class DeviceDecisionError(RuntimeError):
    """Refused device state change (admin lock, unknown device)."""


def _apply_decision(
    db: Session,
    device: ActiveSyncDevice,
    *,
    status: str,
    source: str,
    actor: str,
    note: str | None,
    blocked_by_admin: bool,
    action: str,
    extra_details: dict | None = None,
) -> ActiveSyncDevice:
    device.status = status
    device.source = source
    device.decided_by = actor
    device.decided_at = _utcnow()
    device.decision_note = note
    device.blocked_by_admin = blocked_by_admin
    db.commit()
    db.refresh(device)

    details = {
        "application_id": device.application_id,
        "device_id": device.device_id,
        "device_type": device.device_type,
        "user_key": device.user_key,
        "status": device.status,
        "by": source,
    }
    if note:
        details["reason"] = note[:512]
    if extra_details:
        details.update(extra_details)
    log_action(
        db,
        actor=actor,
        action=action,
        target=_app_slug(db, device.application_id),
        details=details,
    )
    return device


def _app_slug(db: Session, application_id: int) -> str | None:
    app = db.get(App, application_id)
    return app.slug if app else None


def admin_block_device(
    db: Session, device: ActiveSyncDevice, *, actor: str, reason: str
) -> ActiveSyncDevice:
    """Hard block — enforced even when the per-app gate is still off."""
    cleaned = (reason or "").strip()
    if not cleaned:
        raise DeviceDecisionError("Une raison est obligatoire pour bloquer un appareil.")
    return _apply_decision(
        db,
        device,
        status=ACTIVESYNC_DEVICE_BLOCKED,
        source="admin",
        actor=actor,
        note=cleaned,
        blocked_by_admin=True,
        action="activesync.device_blocked",
    )


def admin_unblock_device(
    db: Session, device: ActiveSyncDevice, *, actor: str
) -> ActiveSyncDevice:
    return _apply_decision(
        db,
        device,
        status=ACTIVESYNC_DEVICE_PENDING,
        source="admin",
        actor=actor,
        note=None,
        blocked_by_admin=False,
        action="activesync.device_unblocked",
    )


def admin_approve_device(
    db: Session, device: ActiveSyncDevice, *, actor: str
) -> ActiveSyncDevice:
    return _apply_decision(
        db,
        device,
        status=ACTIVESYNC_DEVICE_APPROVED,
        source="admin",
        actor=actor,
        note=None,
        blocked_by_admin=False,
        action="activesync.device_approved",
    )


def link_devices_to_keycloak_user(
    db: Session,
    *,
    devices: list[ActiveSyncDevice],
    keycloak_user_id: str | None,
    realm_id: int | None,
) -> None:
    """Best-effort identity backfill, outside the hot path.

    The EAS flow only knows an email; the admin fiche knows both. Filling the
    link here costs nothing and never gates a device.
    """
    if not keycloak_user_id:
        return
    changed = False
    for device in devices:
        if not device.keycloak_user_id:
            device.keycloak_user_id = keycloak_user_id
            changed = True
        if realm_id and not device.realm_id:
            device.realm_id = realm_id
            changed = True
    if not changed:
        return
    try:
        db.commit()
    except SQLAlchemyError:
        logger.exception("activesync keycloak link failed user=%s", keycloak_user_id)
        try:
            db.rollback()
        except SQLAlchemyError:
            logger.exception("activesync keycloak link rollback failed")


def devices_for_identities(
    db: Session,
    *,
    user_keys: list[str],
    keycloak_user_id: str | None = None,
) -> list[ActiveSyncDevice]:
    """Devices of one person, matched on the EAS identity or the Keycloak id."""
    keys = sorted({normalize_user_key(k) for k in user_keys if normalize_user_key(k)})
    if not keys and not keycloak_user_id:
        return []
    clauses = []
    if keys:
        clauses.append(ActiveSyncDevice.user_key.in_(keys))
    if keycloak_user_id:
        clauses.append(ActiveSyncDevice.keycloak_user_id == keycloak_user_id)
    return (
        db.query(ActiveSyncDevice)
        .filter(or_(*clauses))
        .order_by(ActiveSyncDevice.last_seen_at.desc())
        .all()
    )
