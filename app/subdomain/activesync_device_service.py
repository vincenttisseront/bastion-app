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
    ACTIVESYNC_DEVICE_REJECTED,
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
from app.subdomain.eas_device_identity import describe_eas_device

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
    """Basic Auth identity used as the inventory key.

    Outlook / Windows EAS often sends ``DOMAIN\\user`` or ``domain\\user@email``.
    The fiche matches on the Keycloak email, so the domain prefix must come off
    here — otherwise the row is written and never joins an identity again.
    """
    value = (raw or "").strip().lower()
    if "\\" in value:
        value = value.rsplit("\\", 1)[-1].strip()
    return value[:255]


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
    """Resolve by clean key, then by a legacy ``DOMAIN\\user`` row for the same device."""
    candidates = list_device_siblings(
        db, application_id=application_id, device_id=device_id
    )
    if not candidates:
        return None
    exact = [d for d in candidates if d.user_key == user_key]
    if exact:
        return _pick_device_winner(exact)
    if user_key:
        legacy = [
            d
            for d in candidates
            if (d.user_key or "").endswith("\\" + user_key)
        ]
        if legacy:
            return _pick_device_winner(legacy)
    return None


def list_device_siblings(
    db: Session, *, application_id: int, device_id: str
) -> list[ActiveSyncDevice]:
    return (
        db.query(ActiveSyncDevice)
        .filter(
            ActiveSyncDevice.application_id == application_id,
            ActiveSyncDevice.device_id == device_id,
        )
        .all()
    )


_STATUS_MERGE_RANK = {
    ACTIVESYNC_DEVICE_BLOCKED: 4,
    ACTIVESYNC_DEVICE_APPROVED: 3,
    ACTIVESYNC_DEVICE_REJECTED: 2,
    ACTIVESYNC_DEVICE_PENDING: 1,
}


def _pick_device_winner(devices: list[ActiveSyncDevice]) -> ActiveSyncDevice:
    return max(devices, key=_device_merge_score)


def _device_merge_score(device: ActiveSyncDevice) -> tuple:
    """Higher wins: admin lock, stronger status, clean key, more hits, older row."""
    clean = 1 if "\\" not in (device.user_key or "") else 0
    return (
        1 if device.blocked_by_admin else 0,
        _STATUS_MERGE_RANK.get(device.status or "", 0),
        clean,
        int(device.request_count or 0),
        -(int(device.id or 0)),
    )


def _absorb_device_into(winner: ActiveSyncDevice, loser: ActiveSyncDevice) -> None:
    """Fold loser stats into winner. Does not delete."""
    winner.request_count = int(winner.request_count or 0) + int(loser.request_count or 0)
    if loser.first_seen_at and (
        winner.first_seen_at is None or loser.first_seen_at < winner.first_seen_at
    ):
        winner.first_seen_at = loser.first_seen_at
    if loser.last_seen_at and (
        winner.last_seen_at is None or loser.last_seen_at > winner.last_seen_at
    ):
        winner.last_seen_at = loser.last_seen_at
        if loser.last_ip:
            winner.last_ip = loser.last_ip
    if loser.device_type and not winner.device_type:
        winner.device_type = loser.device_type
    if loser.user_agent and (
        not winner.user_agent or len(loser.user_agent) > len(winner.user_agent or "")
    ):
        winner.user_agent = loser.user_agent
    if loser.client_kind and not winner.client_kind:
        winner.client_kind = loser.client_kind
    if loser.keycloak_user_id and not winner.keycloak_user_id:
        winner.keycloak_user_id = loser.keycloak_user_id
    if loser.realm_id and not winner.realm_id:
        winner.realm_id = loser.realm_id
    if loser.friendly_name and not winner.friendly_name:
        winner.friendly_name = loser.friendly_name
    if loser.blocked_by_admin:
        winner.blocked_by_admin = True
    # Keep the stronger decision fields when the loser outranks on status.
    if _STATUS_MERGE_RANK.get(loser.status or "", 0) > _STATUS_MERGE_RANK.get(
        winner.status or "", 0
    ):
        winner.status = loser.status
        winner.source = loser.source
        winner.decided_by = loser.decided_by
        winner.decided_at = loser.decided_at
        winner.decision_note = loser.decision_note
    elif (
        loser.decided_by
        and not winner.decided_by
        and winner.status == loser.status
    ):
        winner.decided_by = loser.decided_by
        winner.decided_at = loser.decided_at
        winner.decision_note = loser.decision_note
    merged = list(winner.sample_source_ips or [])
    for ip in loser.sample_source_ips or []:
        if ip and ip not in merged and len(merged) < ACTIVESYNC_DEVICE_MAX_SAMPLE_IPS:
            merged.append(ip)
    winner.sample_source_ips = merged
    clean = normalize_user_key(winner.user_key) or normalize_user_key(loser.user_key)
    if clean:
        winner.user_key = clean


def merge_device_duplicates(
    db: Session, devices: list[ActiveSyncDevice]
) -> list[ActiveSyncDevice]:
    """One physical phone = one row. Collapse ``(application_id, device_id)`` twins.

    Outlook invents ``DOMAIN\\email`` and the bare email as two keys; before
    normalization both were inserted. Repair rewrites collide on the unique
    constraint and leave both — the fiche then lists the same DeviceId twice.
    """
    if not devices:
        return []
    groups: dict[tuple[int, str], list[ActiveSyncDevice]] = {}
    for device in devices:
        groups.setdefault((device.application_id, device.device_id), []).append(device)

    survivors: list[ActiveSyncDevice] = []
    changed = False
    for group in groups.values():
        if len(group) == 1:
            only = group[0]
            clean = normalize_user_key(only.user_key)
            if clean and clean != only.user_key:
                only.user_key = clean
                changed = True
            survivors.append(only)
            continue
        winner = _pick_device_winner(group)
        for loser in group:
            if loser is winner:
                continue
            _absorb_device_into(winner, loser)
            db.delete(loser)
            changed = True
        survivors.append(winner)

    if not changed:
        return survivors
    try:
        db.commit()
    except SQLAlchemyError:
        logger.exception("activesync duplicate merge failed")
        try:
            db.rollback()
        except SQLAlchemyError:
            logger.exception("activesync duplicate merge rollback failed")
        # Fall back to an in-memory dedupe so the UI never double-lists.
        seen: set[tuple[int, str]] = set()
        unique: list[ActiveSyncDevice] = []
        for device in sorted(devices, key=_device_merge_score, reverse=True):
            key = (device.application_id, device.device_id)
            if key in seen:
                continue
            seen.add(key)
            unique.append(device)
        return unique
    return survivors


def collapse_siblings_for_device(
    db: Session, *, application_id: int, device_id: str, keep: ActiveSyncDevice
) -> ActiveSyncDevice:
    """After a sighting, absorb any other rows for the same physical DeviceId."""
    siblings = list_device_siblings(
        db, application_id=application_id, device_id=device_id
    )
    if len(siblings) <= 1:
        only = siblings[0] if siblings else keep
        clean = normalize_user_key(only.user_key)
        if clean and clean != only.user_key:
            only.user_key = clean
            try:
                db.commit()
            except SQLAlchemyError:
                logger.exception("activesync user_key rewrite failed")
                try:
                    db.rollback()
                except SQLAlchemyError:
                    pass
        return only
    merged = merge_device_duplicates(db, siblings)
    return merged[0] if merged else keep


def reconcile_duplicate_devices(db: Session, *, limit: int = 200) -> int:
    """Scan the inventory for twin DeviceIds and collapse them.

    Needed on the pending queue: a filter on ``status=pending`` only sees the
    dirty twin, not the already-approved clean row, so list-local merge misses.
    """
    from sqlalchemy import func

    dup_rows = (
        db.query(
            ActiveSyncDevice.application_id,
            ActiveSyncDevice.device_id,
        )
        .group_by(ActiveSyncDevice.application_id, ActiveSyncDevice.device_id)
        .having(func.count(ActiveSyncDevice.id) > 1)
        .limit(limit)
        .all()
    )
    if not dup_rows:
        return 0
    devices: list[ActiveSyncDevice] = []
    for application_id, device_id in dup_rows:
        devices.extend(
            list_device_siblings(
                db, application_id=application_id, device_id=device_id
            )
        )
    before = len(devices)
    survivors = merge_device_duplicates(db, devices)
    return max(0, before - len(survivors))


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

    # Collapse DOMAIN\email twins before rewriting user_key (unique constraint).
    device = collapse_siblings_for_device(
        db, application_id=app.id, device_id=device_id, keep=device
    )

    should_write, hits, ips = _claim_sighting(key, client_ip)
    if not should_write:
        return device

    try:
        # Rewrite a legacy DOMAIN\user row onto the clean key so the fiche
        # and future lookups share one identity.
        if device.user_key != user_key:
            device.user_key = user_key
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
        device = collapse_siblings_for_device(
            db, application_id=app.id, device_id=device_id, keep=device
        )
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
    # Same physical phone under a dirty key must not become a second row.
    siblings = list_device_siblings(
        db, application_id=app.id, device_id=device_id
    )
    if siblings:
        device = collapse_siblings_for_device(
            db, application_id=app.id, device_id=device_id, keep=siblings[0]
        )
        now = _utcnow()
        try:
            if device.user_key != user_key:
                device.user_key = user_key
            device.last_seen_at = now
            device.request_count = int(device.request_count or 0) + 1
            if client_ip:
                device.last_ip = client_ip
                sample = list(device.sample_source_ips or [])
                if (
                    client_ip not in sample
                    and len(sample) < ACTIVESYNC_DEVICE_MAX_SAMPLE_IPS
                ):
                    sample.append(client_ip)
                    device.sample_source_ips = sample
            if device_type:
                device.device_type = device_type
            if user_agent:
                device.user_agent = user_agent[:512]
            if client_kind:
                device.client_kind = client_kind
            db.commit()
        except SQLAlchemyError:
            logger.exception(
                "activesync sibling sighting failed device_id=%s", device_id
            )
            try:
                db.rollback()
            except SQLAlchemyError:
                pass
            device = collapse_siblings_for_device(
                db, application_id=app.id, device_id=device_id, keep=device
            )
        return device

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
            # Sibling under another key form — fold instead of failing open.
            siblings = list_device_siblings(
                db, application_id=app.id, device_id=device_id
            )
            if siblings:
                return collapse_siblings_for_device(
                    db,
                    application_id=app.id,
                    device_id=device_id,
                    keep=siblings[0],
                )
            logger.exception("activesync device insert failed device_id=%s", device_id)
            return None
        return collapse_siblings_for_device(
            db, application_id=app.id, device_id=device_id, keep=existing
        )

    identity = describe_eas_device(
        device_id=device_id,
        device_type=device_type,
        user_agent=user_agent,
        client_kind=client_kind,
    )
    details = {
        "application_id": app.id,
        "device_id": device_id,
        "device_type": device_type,
        "client_kind": client_kind,
        "user_agent": (user_agent or "")[:512] or None,
        "status": device.status,
        "device_control": bool(app.activesync_device_control),
    }
    for key in ("apple_serial", "model_label", "display_name"):
        value = identity.get(key)
        if value:
            details[key] = value
    log_action(
        db,
        actor=user_key,
        action="activesync.device_discovered",
        target=app.slug,
        details=details,
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


def repair_domain_prefixed_user_keys(
    db: Session, devices: list[ActiveSyncDevice]
) -> list[ActiveSyncDevice]:
    """Rewrite dirty keys and collapse twin DeviceIds (fiche / pending queue)."""
    return merge_device_duplicates(db, devices)


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
    """Devices of one person, matched on the EAS identity or the Keycloak id.

    Also matches legacy ``DOMAIN\\email`` rows so a fiche opened before the next
    sync still sees the phones already inventoried under a dirty key.
    """
    keys = sorted({normalize_user_key(k) for k in user_keys if normalize_user_key(k)})
    if not keys and not keycloak_user_id:
        return []
    clauses = []
    if keys:
        clauses.append(ActiveSyncDevice.user_key.in_(keys))
        for k in keys:
            clauses.append(ActiveSyncDevice.user_key.endswith("\\" + k))
    if keycloak_user_id:
        clauses.append(ActiveSyncDevice.keycloak_user_id == keycloak_user_id)
    return (
        db.query(ActiveSyncDevice)
        .filter(or_(*clauses))
        .order_by(ActiveSyncDevice.last_seen_at.desc())
        .all()
    )
