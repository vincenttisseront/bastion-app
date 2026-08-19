"""WAF admin service — profiles, exclusions, apply + audit."""

from __future__ import annotations

from typing import Any, Callable

from sqlalchemy.orm import Session

from app.audit import log_action
from app.bastion.nginx_waf_export import (
    ANOMALY_MAX,
    ANOMALY_MIN,
    MODE_DETECTION,
    MODE_OFF,
    MODE_ON,
    VALID_MODES,
    apply_waf_exports,
    clamp_anomaly_threshold,
    ensure_active_profile,
    get_active_profile,
    read_effective_status,
    record_waf_apply_metadata,
)
from app.models import WafExclusion, WafProfile
from app.sso_settings import Settings

PRESET_VALUES: dict[str, dict[str, Any]] = {
    "Développement": {
        "mode": MODE_DETECTION,
        "anomaly_threshold": 10,
        "portal_login_rate": 10,
        "portal_api_rate": 100,
    },
    "Préproduction": {
        "mode": MODE_ON,
        "anomaly_threshold": 7,
        "portal_login_rate": 3,
        "portal_api_rate": 30,
    },
    "Production": {
        "mode": MODE_ON,
        "anomaly_threshold": 5,
        "portal_login_rate": 3,
        "portal_api_rate": 30,
    },
}


def list_profiles(db: Session) -> list[WafProfile]:
    return db.query(WafProfile).order_by(WafProfile.name).all()


def list_exclusions(db: Session, *, active_only: bool = False) -> list[WafExclusion]:
    q = db.query(WafExclusion).order_by(WafExclusion.id.desc())
    if active_only:
        q = q.filter_by(active=True)
    return q.all()


def update_active_profile(
    db: Session,
    *,
    mode: str,
    anomaly_threshold: int,
    profile_name: str | None = None,
    ip_deny_min_occurrences: int | None = None,
    portal_login_rate: int | None = None,
    portal_api_rate: int | None = None,
    portal_login_burst: int | None = None,
    portal_api_burst: int | None = None,
    actor: str,
    ip_address: str | None = None,
) -> WafProfile:
    if mode not in VALID_MODES:
        raise ValueError(f"mode invalide: {mode}")
    if anomaly_threshold < ANOMALY_MIN or anomaly_threshold > ANOMALY_MAX:
        raise ValueError(
            f"seuil d'anomalie hors borne [{ANOMALY_MIN}, {ANOMALY_MAX}]: {anomaly_threshold}"
        )

    if profile_name and profile_name in PRESET_VALUES:
        for row in db.query(WafProfile).all():
            row.is_active = row.name == profile_name
        profile = db.query(WafProfile).filter_by(name=profile_name).one()
        preset = PRESET_VALUES[profile_name]
        old_mode, old_thr = profile.mode, profile.anomaly_threshold
        profile.mode = str(preset["mode"])
        profile.anomaly_threshold = int(preset["anomaly_threshold"])
        profile.portal_login_rate = int(preset["portal_login_rate"])
        profile.portal_api_rate = int(preset["portal_api_rate"])
        # Allow form overrides on top of preset when provided.
        if mode in VALID_MODES:
            profile.mode = mode
        profile.anomaly_threshold = clamp_anomaly_threshold(anomaly_threshold)
    else:
        # Custom: keep/update active profile in place (or create Custom).
        profile = get_active_profile(db) or ensure_active_profile(db)
        old_mode, old_thr = profile.mode, profile.anomaly_threshold
        if profile.name in PRESET_VALUES:
            # Detach presets; activate/create Custom.
            for row in db.query(WafProfile).all():
                row.is_active = False
            custom = db.query(WafProfile).filter_by(name="Custom").first()
            if not custom:
                custom = WafProfile(
                    name="Custom",
                    mode=mode,
                    anomaly_threshold=clamp_anomaly_threshold(anomaly_threshold),
                    is_active=True,
                    created_by=actor,
                )
                db.add(custom)
            else:
                custom.is_active = True
                custom.mode = mode
                custom.anomaly_threshold = clamp_anomaly_threshold(anomaly_threshold)
            profile = custom
        else:
            profile.mode = mode
            profile.anomaly_threshold = clamp_anomaly_threshold(anomaly_threshold)

    if ip_deny_min_occurrences is not None:
        profile.ip_deny_min_occurrences = max(1, int(ip_deny_min_occurrences))
    if portal_login_rate is not None:
        profile.portal_login_rate = max(1, int(portal_login_rate))
    if portal_api_rate is not None:
        profile.portal_api_rate = max(1, int(portal_api_rate))
    if portal_login_burst is not None:
        profile.portal_login_burst = max(0, int(portal_login_burst))
    if portal_api_burst is not None:
        profile.portal_api_burst = max(0, int(portal_api_burst))

    db.commit()
    db.refresh(profile)

    if old_mode != profile.mode:
        log_action(
            db,
            actor=actor,
            action="security.waf.mode_changed",
            target=profile.name,
            details={"old": old_mode, "new": profile.mode},
            ip_address=ip_address,
        )
    if old_thr != profile.anomaly_threshold:
        log_action(
            db,
            actor=actor,
            action="security.waf.threshold_changed",
            target=profile.name,
            details={"old": old_thr, "new": profile.anomaly_threshold},
            ip_address=ip_address,
        )
    db.commit()
    return profile


def add_exclusion(
    db: Session,
    *,
    reason: str,
    crs_rule_id: int | None,
    uri_pattern: str | None,
    host: str | None,
    actor: str,
    ip_address: str | None = None,
) -> WafExclusion:
    reason_s = (reason or "").strip()
    if not reason_s:
        raise ValueError("raison obligatoire")
    uri = (uri_pattern or "").strip() or None
    host_s = (host or "").strip() or None
    if not uri and not host_s:
        raise ValueError("uri_pattern ou host requis")
    if crs_rule_id is None:
        raise ValueError("crs_rule_id requis")
    row = WafExclusion(
        reason=reason_s,
        crs_rule_id=int(crs_rule_id),
        uri_pattern=uri,
        host=host_s,
        active=True,
        created_by=actor,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="security.waf.exclusion_added",
        target=str(row.id),
        details={
            "crs_rule_id": row.crs_rule_id,
            "uri_pattern": row.uri_pattern,
            "host": row.host,
            "reason": row.reason,
        },
        ip_address=ip_address,
    )
    db.commit()
    return row


def disable_exclusion(
    db: Session,
    exclusion_id: int,
    *,
    actor: str,
    ip_address: str | None = None,
) -> WafExclusion:
    row = db.query(WafExclusion).filter_by(id=exclusion_id).first()
    if not row:
        raise ValueError("exclusion introuvable")
    row.active = False
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="security.waf.exclusion_disabled",
        target=str(row.id),
        details={"crs_rule_id": row.crs_rule_id, "reason": row.reason},
        ip_address=ip_address,
    )
    db.commit()
    return row


def apply_waf(
    db: Session,
    settings: Settings,
    *,
    actor: str,
    ip_address: str | None = None,
    validate: Callable[[Settings], tuple[bool, str]] | None = None,
) -> dict[str, Any]:
    ensure_active_profile(db)
    result = apply_waf_exports(db, settings, validate=validate)
    if result.get("ok"):
        record_waf_apply_metadata(
            settings,
            actor=actor,
            nginx_t_ok=True,
            nginx_t_detail=result.get("validate_detail") or "nginx -t ok",
        )
    log_action(
        db,
        actor=actor,
        action="security.waf.apply",
        target=get_active_profile(db).name if get_active_profile(db) else None,
        details={
            "ok": result.get("ok"),
            "error": result.get("error"),
            "paths": list((result.get("paths") or {}).keys()),
        },
        ip_address=ip_address,
    )
    db.commit()
    result["effective"] = read_effective_status(settings)
    return result
