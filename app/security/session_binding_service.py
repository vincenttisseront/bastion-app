"""Session identity binding (IP/fingerprint) for SSO and break-glass families."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import BreakGlassSession, SsoSessionAnchor, utcnow
from app.request_client_ip import client_ip_from_request
from app.security.identity_binding import (
    classify_drift,
    fingerprint_from_request,
    oauth2_proxy_cookie_hash,
    subnet_from_request,
)

logger = logging.getLogger(__name__)

# Retention for SSO anchors after last_seen (oauth2 cookie TTL is shorter;
# this only bounds orphaned DB rows). Confirmed default for V1: 30 days.
SSO_SESSION_ANCHOR_RETENTION_DAYS = 30

ACTION_HIJACK = "session_hijack_suspected"
ACTION_DRIFT = "session_fingerprint_drift"


def _signals(request: Request) -> tuple[str, str]:
    return subnet_from_request(request), fingerprint_from_request(request)


def _same(a: str | None, b: str | None) -> bool:
    return (a or "") == (b or "")


def apply_breakglass_login_anchor(
    db: Session,
    row: BreakGlassSession,
    request: Request,
) -> None:
    """Stamp first/last identity signals at break-glass login."""
    subnet, fp = _signals(request)
    row.first_ip_subnet = subnet or None
    row.first_fingerprint_hash = fp or None
    row.last_ip_subnet = subnet or None
    row.last_fingerprint_hash = fp or None
    if row.mismatch_count is None:
        row.mismatch_count = 0
    db.flush()


def evaluate_breakglass_binding(
    db: Session,
    request: Request,
    *,
    jti: str,
    username: str,
) -> bool:
    """
    Compare current request to login anchor for a break-glass jti.

    Returns True if the request may proceed, False if it must be rejected (401).
    Missing anchor columns (warm deploy) → treat as first sight and allow.
    """
    row = db.query(BreakGlassSession).filter_by(jti=jti).first()
    if row is None:
        return True

    subnet, fp = _signals(request)
    client_ip = client_ip_from_request(request)

    if not (row.first_ip_subnet or row.first_fingerprint_hash):
        row.first_ip_subnet = subnet or None
        row.first_fingerprint_hash = fp or None
        row.last_ip_subnet = subnet or None
        row.last_fingerprint_hash = fp or None
        if row.mismatch_count is None:
            row.mismatch_count = 0
        db.flush()
        return True

    drift = classify_drift(
        _same(row.first_ip_subnet, subnet),
        _same(row.first_fingerprint_hash, fp),
    )

    if drift == "strong":
        row.mismatch_count = int(row.mismatch_count or 0) + 1
        db.flush()
        log_action(
            db,
            actor=username or "breakglass",
            action=ACTION_HIJACK,
            target=jti,
            details={
                "family": "breakglass",
                "jti": jti,
                "username": username,
                "expected_subnet": row.first_ip_subnet,
                "observed_subnet": subnet or None,
                "expected_fingerprint": row.first_fingerprint_hash,
                "observed_fingerprint": fp or None,
                "mismatch_count": row.mismatch_count,
                "policy": "stepup_401",
            },
            ip_address=client_ip or None,
        )
        return False

    if drift == "weak":
        log_action(
            db,
            actor=username or "breakglass",
            action=ACTION_DRIFT,
            target=jti,
            details={
                "family": "breakglass",
                "jti": jti,
                "expected_fingerprint": row.first_fingerprint_hash,
                "observed_fingerprint": fp or None,
                "subnet": subnet or None,
            },
            ip_address=client_ip or None,
        )

    row.last_ip_subnet = subnet or None
    row.last_fingerprint_hash = fp or None
    db.flush()
    return True


def evaluate_sso_binding(
    db: Session,
    request: Request,
    *,
    username: str | None = None,
    keycloak_user_id: str | None = None,
) -> dict[str, Any] | None:
    """
    Upsert SSO cookie anchor and apply WARN-only policy on strong drift.

    Always allows the request (V1). Returns a public summary dict or None if
    no oauth2-proxy cookie is present.

    ``username`` should be a human label (email / preferred_username). Pass the
    Keycloak subject separately as ``keycloak_user_id`` — never as the only
    display identity for audit rows.
    """
    from app.web.user_context import _human_label, looks_like_uuid

    cookie_hash = oauth2_proxy_cookie_hash(request)
    if not cookie_hash:
        return None

    subnet, fp = _signals(request)
    client_ip = client_ip_from_request(request)
    readable = _human_label(username)
    kc_id = (keycloak_user_id or "").strip() or None
    if not kc_id and looks_like_uuid(username):
        kc_id = (username or "").strip()
        readable = None
    label_for_anchor = readable or kc_id
    actor = readable or "unknown"
    now = utcnow()

    row = db.query(SsoSessionAnchor).filter_by(cookie_hash=cookie_hash).first()
    if row is None:
        row = SsoSessionAnchor(
            cookie_hash=cookie_hash,
            username=label_for_anchor if label_for_anchor else None,
            first_ip_subnet=subnet or None,
            first_fingerprint_hash=fp or None,
            last_ip_subnet=subnet or None,
            last_fingerprint_hash=fp or None,
            mismatch_count=0,
            first_seen=now,
            last_seen=now,
        )
        db.add(row)
        db.flush()
        # New oauth2 cookie → count as one successful SSO login (not every auth_request).
        try:
            from app.security.banning.engine import record_successful_login

            record_successful_login(
                db,
                ip=client_ip or "",
                username=readable or label_for_anchor or "sso",
            )
        except Exception:
            logger.exception("record_successful_login after new SSO anchor failed")
        return {
            "cookie_hash_prefix": cookie_hash[:12],
            "mismatch_count": 0,
            "drift": "none",
            "first_ip_subnet": row.first_ip_subnet,
            "last_ip_subnet": row.last_ip_subnet,
            "first_fingerprint_hash": row.first_fingerprint_hash,
            "last_fingerprint_hash": row.last_fingerprint_hash,
        }

    # Upgrade stored label when we learn a human identity (email / preferred).
    if readable and (not row.username or looks_like_uuid(row.username)):
        row.username = readable
    elif label_for_anchor and not row.username:
        row.username = label_for_anchor

    row_label = _human_label(row.username)
    audit_actor = readable or row_label or "unknown"
    if not (row.first_ip_subnet or row.first_fingerprint_hash):
        row.first_ip_subnet = subnet or None
        row.first_fingerprint_hash = fp or None
        drift = "none"
    else:
        drift = classify_drift(
            _same(row.first_ip_subnet, subnet),
            _same(row.first_fingerprint_hash, fp),
        )

    def _drift_details(**extra: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "family": "sso",
            "cookie_hash_prefix": cookie_hash[:16],
            **extra,
        }
        if row_label:
            payload["username"] = row_label
        elif readable:
            payload["username"] = readable
        if kc_id:
            payload["keycloak_user_id"] = kc_id
        elif looks_like_uuid(row.username):
            payload["keycloak_user_id"] = row.username
        return payload

    if drift == "strong":
        row.mismatch_count = int(row.mismatch_count or 0) + 1
        log_action(
            db,
            actor=audit_actor,
            action=ACTION_HIJACK,
            target=cookie_hash[:16],
            details=_drift_details(
                expected_subnet=row.first_ip_subnet,
                observed_subnet=subnet or None,
                expected_fingerprint=row.first_fingerprint_hash,
                observed_fingerprint=fp or None,
                mismatch_count=row.mismatch_count,
                policy="warn_only",
            ),
            ip_address=client_ip or None,
        )
    elif drift == "weak":
        log_action(
            db,
            actor=audit_actor,
            action=ACTION_DRIFT,
            target=cookie_hash[:16],
            details=_drift_details(
                expected_fingerprint=row.first_fingerprint_hash,
                observed_fingerprint=fp or None,
                subnet=subnet or None,
            ),
            ip_address=client_ip or None,
        )

    row.last_ip_subnet = subnet or None
    row.last_fingerprint_hash = fp or None
    row.last_seen = now
    db.flush()
    return {
        "cookie_hash_prefix": cookie_hash[:12],
        "mismatch_count": int(row.mismatch_count or 0),
        "drift": drift,
        "first_ip_subnet": row.first_ip_subnet,
        "last_ip_subnet": row.last_ip_subnet,
        "first_fingerprint_hash": row.first_fingerprint_hash,
        "last_fingerprint_hash": row.last_fingerprint_hash,
    }


def purge_stale_sso_session_anchors(
    db: Session,
    *,
    retention_days: int = SSO_SESSION_ANCHOR_RETENTION_DAYS,
) -> int:
    """Delete SSO anchors whose last_seen is older than retention_days."""
    cutoff = utcnow() - __import__("datetime").timedelta(days=max(0, retention_days))
    rows = (
        db.query(SsoSessionAnchor)
        .filter(SsoSessionAnchor.last_seen < cutoff)
        .all()
    )
    for row in rows:
        db.delete(row)
    if rows:
        db.commit()
    return len(rows)


def binding_summary_for_breakglass_jti(
    db: Session, jti: str | None
) -> dict[str, Any] | None:
    if not jti:
        return None
    row = db.query(BreakGlassSession).filter_by(jti=jti).first()
    if row is None:
        return None
    count = int(row.mismatch_count or 0)
    if count <= 0 and not row.first_ip_subnet:
        return None
    return {
        "mismatch_count": count,
        "unusual": count > 0,
        "first_ip_subnet": row.first_ip_subnet,
        "last_ip_subnet": row.last_ip_subnet,
        "first_fingerprint_hash": row.first_fingerprint_hash,
        "last_fingerprint_hash": row.last_fingerprint_hash,
    }


def binding_summary_for_sso_user(
    db: Session, *, username: str | None, email: str | None
) -> dict[str, Any] | None:
    """Best-effort SSO binding summary for /sessions (max mismatch for this user)."""
    candidates = {
        (username or "").strip().lower(),
        (email or "").strip().lower(),
    }
    candidates.discard("")
    if not candidates:
        return None
    rows = (
        db.query(SsoSessionAnchor)
        .filter(SsoSessionAnchor.username.isnot(None))
        .order_by(SsoSessionAnchor.last_seen.desc())
        .limit(50)
        .all()
    )
    best: SsoSessionAnchor | None = None
    for row in rows:
        uname = (row.username or "").strip().lower()
        if uname in candidates:
            if best is None or int(row.mismatch_count or 0) > int(
                best.mismatch_count or 0
            ):
                best = row
    if best is None:
        return None
    count = int(best.mismatch_count or 0)
    return {
        "mismatch_count": count,
        "unusual": count > 0,
        "first_ip_subnet": best.first_ip_subnet,
        "last_ip_subnet": best.last_ip_subnet,
        "first_fingerprint_hash": best.first_fingerprint_hash,
        "last_fingerprint_hash": best.last_fingerprint_hash,
    }
