"""Break-glass login, JWT cookie, session jti denylist, and admin routes."""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import log_action
from app.breakglass_store import verify_breakglass_password
from app.database import get_db
from app.models import BreakGlassSession, utcnow
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings

logger = logging.getLogger(__name__)

COOKIE_NAME = "bg_session"
# Absolute TTL — PROPOSED / documented in architecture (8h). Validated on every decode.
COOKIE_MAX_AGE = 8 * 3600
# Idle timeout — PROPOSED for admin break-glass (stricter than SSO). Sliding via ``last`` claim.
IDLE_TIMEOUT_SECONDS = 30 * 60
# Re-issue cookie at most this often when sliding idle (avoid Set-Cookie spam).
# Kept for maybe_refresh; auth_request paths now rotate jti every request instead.
_IDLE_TOUCH_MIN_SECONDS = 60
# Keep revoked/expired session rows for audit before purge (documented, not arbitrary).
BREAKGLASS_SESSION_RETENTION_DAYS = 7
# Grace window after rotation: old cookie still accepted briefly (parallel requests / race).
GRACE_WINDOW_SECONDS = 5

# Process-lifetime secret when BREAKGLASS_JWT_SECRET is unset (dev / first boot).
_EPHEMERAL_JWT_SECRET: str | None = None

# Public: login / logout (cannot require an existing portal session).
router = APIRouter(prefix="/api/admin/breakglass", tags=["breakglass"])
# Admin list/revoke — ``require_admin`` attached in ``main`` (avoids circular import
# with ``user_context`` which imports this module for cookie validation).
admin_router = APIRouter(prefix="/api/admin/breakglass", tags=["breakglass"])


class BreakglassLoginBody(BaseModel):
    username: str
    password: str


class BreakglassRevokeBody(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


class BreakglassAuthResult:
    """Outcome of protected-request processing (rotation / replay / grace)."""

    __slots__ = ("ok", "payload", "set_cookie", "username", "jti", "chain_id")

    def __init__(
        self,
        *,
        ok: bool,
        payload: dict[str, Any] | None = None,
        set_cookie: str | None = None,
        username: str = "",
        jti: str = "",
        chain_id: str | None = None,
    ) -> None:
        self.ok = ok
        self.payload = payload
        self.set_cookie = set_cookie
        self.username = username
        self.jti = jti
        self.chain_id = chain_id


def reset_breakglass_ephemeral_secret_for_tests() -> None:
    """Clear process-lifetime auto-generated JWT secret (tests only)."""
    global _EPHEMERAL_JWT_SECRET
    _EPHEMERAL_JWT_SECRET = None


def _legacy_breakglass_hmac_secret(settings: Settings) -> str:
    return (settings.vault_portal_internal_token or "").strip()


def resolve_breakglass_signing_secret_with_source(
    settings: Settings,
    db: Session | None = None,
) -> tuple[str, "SigningSource"]:
    """
    Secret used to *sign* new ``bg_session`` JWTs (single active source).

    Priority:
    1. ``BREAKGLASS_JWT_SECRET`` (env / emergency override)
    2. DB secret in ``portal_settings`` (Ansible / Admin UI — preferred)
    3. Legacy ``VAULT_PORTAL_INTERNAL_TOKEN`` (non-production only)
    4. Process-lifetime ephemeral (dev / last resort)

    Returns ``(secret, source)`` where source is env|ui|legacy|ephemeral.
    """
    from app.breakglass_secret_service import SigningSource, get_ui_breakglass_secret

    dedicated = (settings.breakglass_jwt_secret or "").strip()
    if dedicated:
        return dedicated, "env"

    ui = get_ui_breakglass_secret(db, settings)
    if ui:
        return ui, "ui"

    if settings.is_production:
        raise RuntimeError(
            "break-glass JWT secret missing in portal_settings "
            "(run: python -m app.runtime_secrets_service ; no VAULT_PORTAL_INTERNAL_TOKEN fallback)"
        )

    legacy = _legacy_breakglass_hmac_secret(settings)
    if legacy:
        logger.warning(
            "BREAKGLASS_JWT_SECRET unset — signing with legacy VAULT_PORTAL_INTERNAL_TOKEN "
            "(disabled in production)"
        )
        return legacy, "legacy"

    global _EPHEMERAL_JWT_SECRET
    if _EPHEMERAL_JWT_SECRET is None:
        _EPHEMERAL_JWT_SECRET = secrets.token_urlsafe(32)
        logger.warning(
            "break-glass JWT secret unset — using ephemeral process secret; "
            "seed via python -m app.runtime_secrets_service or Admin → Sécurité"
        )
    source: SigningSource = "ephemeral"
    return _EPHEMERAL_JWT_SECRET, source


def resolve_breakglass_signing_secret(
    settings: Settings,
    db: Session | None = None,
) -> str:
    """Secret used to *sign* new ``bg_session`` JWTs (see ``*_with_source``)."""
    secret, _source = resolve_breakglass_signing_secret_with_source(settings, db=db)
    return secret


def _validation_secrets(
    settings: Settings,
    db: Session | None = None,
) -> list[tuple[str, str]]:
    """
    Ordered unique secrets accepted during transition.

    Signing uses a single source; validation may accept env, UI current/previous,
    and legacy vault token when fallback is enabled.
    """
    from app.breakglass_secret_service import (
        get_ui_breakglass_previous_secret,
        get_ui_breakglass_secret,
        secrets_equal,
    )

    out: list[tuple[str, str]] = []

    def add(secret: str | None, label: str) -> None:
        if not secret:
            return
        if any(secrets_equal(secret, existing) for existing, _ in out):
            return
        out.append((secret, label))

    primary, source = resolve_breakglass_signing_secret_with_source(settings, db=db)
    add(primary, source)
    add(get_ui_breakglass_secret(db, settings), "ui")
    add(get_ui_breakglass_previous_secret(db, settings), "ui_previous")
    if settings.breakglass_jwt_secret_fallback_enabled:
        add(_legacy_breakglass_hmac_secret(settings), "legacy")
    elif settings.is_production:
        # Production always refuses vault-token legacy (validator also forces flag off).
        pass
    return out


def decode_breakglass_token_with_fallback(
    cookie_value: str,
    settings: Settings,
    db: Session | None = None,
) -> tuple[dict[str, Any] | None, bool]:
    """
    Decode ``bg_session`` trying active + transition secrets.

    Returns ``(payload, used_legacy_fallback)`` — legacy means vault token only.
    """
    for secret, label in _validation_secrets(settings, db=db):
        payload = decode_breakglass_token(cookie_value, secret)
        if payload is not None:
            used_legacy = label == "legacy"
            if used_legacy:
                logger.info(
                    "breakglass JWT accepted via legacy VAULT_PORTAL_INTERNAL_TOKEN "
                    "fallback (disable BREAKGLASS_JWT_SECRET_FALLBACK_ENABLED once "
                    "all sessions renewed)"
                )
            return payload, used_legacy
    return None, False


def _aware_exp(exp: Any) -> datetime | None:
    if isinstance(exp, datetime):
        return exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
    if isinstance(exp, (int, float)):
        return datetime.fromtimestamp(exp, tz=timezone.utc)
    return None


def create_breakglass_token(
    username: str,
    secret: str,
    *,
    jti: str | None = None,
) -> str:
    """Build a break-glass JWT. Always includes a unique ``jti`` claim."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(seconds=COOKIE_MAX_AGE),
        "last": int(now.timestamp()),
        "type": "bg",
        "jti": jti or str(uuid4()),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def register_breakglass_session(
    db: Session,
    *,
    jti: str,
    username: str,
    expires_at: datetime,
    issued_at: datetime | None = None,
    chain_id: str | None = None,
) -> BreakGlassSession:
    """Persist a newly issued break-glass session (metadata only — no credentials)."""
    row = BreakGlassSession(
        jti=jti,
        username=username,
        issued_at=issued_at or utcnow(),
        expires_at=expires_at,
        revoked=False,
        chain_id=chain_id or jti,
        chain_revoked=False,
        superseded_by=None,
        superseded_at=None,
    )
    db.add(row)
    db.flush()
    return row


def issue_breakglass_token(
    db: Session,
    username: str,
    secret: str,
    *,
    request: Request | None = None,
) -> tuple[str, str]:
    """Create JWT + BreakGlassSession row. Returns ``(token, jti)``."""
    jti = str(uuid4())
    token = create_breakglass_token(username, secret, jti=jti)
    payload = jwt.decode(token, secret, algorithms=["HS256"])
    expires_at = _aware_exp(payload.get("exp"))
    if expires_at is None:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=COOKIE_MAX_AGE)
    issued = payload.get("iat")
    issued_at = _aware_exp(issued) or datetime.now(timezone.utc)
    row = register_breakglass_session(
        db,
        jti=jti,
        username=username,
        expires_at=expires_at,
        issued_at=issued_at,
        chain_id=jti,
    )
    if request is not None:
        from app.security.session_binding_service import apply_breakglass_login_anchor

        apply_breakglass_login_anchor(db, row, request)
    return token, jti


def ensure_breakglass_chain_id(row: BreakGlassSession) -> str:
    """Warm-deploy: treat missing chain_id as a single-jti chain."""
    if not (row.chain_id or "").strip():
        row.chain_id = row.jti
    return str(row.chain_id)


def _within_grace(row: BreakGlassSession, *, now: datetime | None = None) -> bool:
    if not row.superseded_by or row.superseded_at is None:
        return False
    now = now or utcnow()
    superseded_at = row.superseded_at
    if superseded_at.tzinfo is None:
        superseded_at = superseded_at.replace(tzinfo=timezone.utc)
    return (now - superseded_at).total_seconds() <= GRACE_WINDOW_SECONDS


def current_chain_tip(
    db: Session, chain_id: str
) -> BreakGlassSession | None:
    """Return the non-superseded row for a chain (current jti)."""
    return (
        db.query(BreakGlassSession)
        .filter(
            BreakGlassSession.chain_id == chain_id,
            BreakGlassSession.superseded_by.is_(None),
        )
        .order_by(BreakGlassSession.issued_at.desc())
        .first()
    )


def mark_chain_revoked(db: Session, chain_id: str) -> int:
    """Set chain_revoked=True on every row of the chain. Returns rows touched."""
    rows = (
        db.query(BreakGlassSession).filter(BreakGlassSession.chain_id == chain_id).all()
    )
    for row in rows:
        row.chain_revoked = True
    db.flush()
    return len(rows)


def is_breakglass_jti_revoked(db: Session, jti: str) -> bool:
    """
    True if this jti must not authenticate.

    Covers explicit admin revoke, whole-chain cut, and superseded cookies outside
    the grace window. Tokens with no registry row keep prior behaviour (not blocked
    solely by missing row — unit tests without register still work).
    """
    if not jti:
        return True
    row = db.query(BreakGlassSession).filter_by(jti=jti).first()
    if row is None:
        return False
    if bool(row.chain_revoked) or bool(row.revoked):
        return True
    if row.superseded_by and not _within_grace(row):
        return True
    return False


def revoke_breakglass_jti(
    db: Session,
    jti: str,
    *,
    revoked_by: str,
    reason: str | None = None,
) -> BreakGlassSession:
    """
    Revoke a break-glass session and cut its entire rotation chain.

    ``revoked*`` fields are set on the targeted jti (audit); ``chain_revoked`` is
    set on every row sharing the same ``chain_id`` (enforcement).
    """
    row = db.query(BreakGlassSession).filter_by(jti=jti).first()
    if row is None:
        raise LookupError("breakglass session not found")
    chain_id = ensure_breakglass_chain_id(row)
    if not row.revoked:
        row.revoked = True
        row.revoked_at = utcnow()
        row.revoked_by = revoked_by
        row.revoked_reason = (reason or "").strip() or None
    mark_chain_revoked(db, chain_id)
    db.flush()
    return row


def encode_breakglass_claims(
    payload: dict[str, Any],
    secret: str,
    *,
    jti: str,
    touch_last: bool = True,
) -> str:
    """Re-encode claims preserving absolute ``exp`` / ``iat``; optionally slide ``last``."""
    now = datetime.now(timezone.utc)
    now_ts = int(now.timestamp())
    exp_dt = _aware_exp(payload.get("exp"))
    if exp_dt is None:
        exp_dt = now + timedelta(seconds=COOKIE_MAX_AGE)
    last = now_ts if touch_last else int(payload.get("last") or now_ts)
    claims = {
        "sub": payload.get("sub"),
        "iat": payload.get("iat"),
        "exp": exp_dt,
        "last": last,
        "type": "bg",
        "jti": jti,
    }
    return jwt.encode(claims, secret, algorithm="HS256")


def rotate_breakglass_session(
    db: Session,
    row: BreakGlassSession,
    payload: dict[str, Any],
    secret: str,
) -> tuple[str, BreakGlassSession]:
    """
    Advance the rotation chain: new jti row + mark old superseded.

    Preserves absolute ``expires_at`` and login identity anchors (first_*).
    """
    chain_id = ensure_breakglass_chain_id(row)
    jti_next = str(uuid4())
    now = utcnow()
    exp_at = row.expires_at
    if exp_at is not None and exp_at.tzinfo is None:
        exp_at = exp_at.replace(tzinfo=timezone.utc)
    new_row = BreakGlassSession(
        jti=jti_next,
        chain_id=chain_id,
        username=row.username,
        issued_at=now,
        expires_at=exp_at,
        revoked=False,
        chain_revoked=False,
        superseded_by=None,
        superseded_at=None,
        first_ip_subnet=row.first_ip_subnet,
        first_fingerprint_hash=row.first_fingerprint_hash,
        last_ip_subnet=row.last_ip_subnet,
        last_fingerprint_hash=row.last_fingerprint_hash,
        mismatch_count=int(row.mismatch_count or 0),
    )
    db.add(new_row)
    row.superseded_by = jti_next
    row.superseded_at = now
    db.flush()
    token = encode_breakglass_claims(payload, secret, jti=jti_next, touch_last=True)
    return token, new_row


def process_breakglass_auth_request(
    db: Session,
    request: Request,
    cookie_value: str,
    settings: Settings,
    *,
    rotate: bool = True,
) -> BreakglassAuthResult:
    """
    Full protected-request pipeline for ``bg_session``.

    Order: decode → chain_revoked → revoked → superseded(+grace) → IP/fingerprint
    → optional rotate (or resync tip on grace) → OK.

    ``rotate=False`` for nginx ``auth_request`` handlers: Set-Cookie on the auth
    subresponse is not forwarded to the browser, so rotating there would mark the
    still-held cookie as superseded and cut the chain after the grace window.
    Rotation must run on the main FastAPI response (middleware) instead.
    """
    from app.security.identity_binding import fingerprint_from_request
    from app.security.session_binding_service import evaluate_breakglass_binding

    payload, _fb = decode_breakglass_token_with_fallback(
        cookie_value, settings, db=db
    )
    if payload is None:
        return BreakglassAuthResult(ok=False)

    jti = payload.get("jti")
    username = str(payload.get("sub") or "breakglass")
    if not jti or not isinstance(jti, str):
        return BreakglassAuthResult(ok=False)

    row = db.query(BreakGlassSession).filter_by(jti=jti).first()
    if row is None:
        # Legacy token without registry: allow without rotation (cannot chain).
        return BreakglassAuthResult(
            ok=True, payload=payload, username=username, jti=jti
        )

    chain_id = ensure_breakglass_chain_id(row)
    client_ip = client_ip_from_request(request)
    fp = fingerprint_from_request(request)

    if bool(row.chain_revoked):
        return BreakglassAuthResult(ok=False)

    if bool(row.revoked):
        return BreakglassAuthResult(ok=False)

    secret = resolve_breakglass_signing_secret(settings, db=db)

    if row.superseded_by is not None:
        if _within_grace(row):
            tip = current_chain_tip(db, chain_id) or row
            if rotate:
                log_action(
                    db,
                    actor=username,
                    action="breakglass_cookie_grace_reuse",
                    target=chain_id,
                    details={
                        "chain_id": chain_id,
                        "jti_presented": jti,
                        "jti_current": tip.jti,
                    },
                    ip_address=client_ip or None,
                )
            if not evaluate_breakglass_binding(
                db, request, jti=tip.jti, username=username
            ):
                return BreakglassAuthResult(ok=False)
            if not rotate:
                return BreakglassAuthResult(
                    ok=True,
                    payload=payload,
                    username=username,
                    jti=tip.jti,
                    chain_id=chain_id,
                )
            tip_token = encode_breakglass_claims(
                payload, secret, jti=tip.jti, touch_last=True
            )
            return BreakglassAuthResult(
                ok=True,
                payload=payload,
                set_cookie=tip_token,
                username=username,
                jti=tip.jti,
                chain_id=chain_id,
            )

        mark_chain_revoked(db, chain_id)
        log_action(
            db,
            actor=username,
            action="breakglass_cookie_replay_detected",
            target=chain_id,
            details={
                "severity": "high",
                "chain_id": chain_id,
                "jti_presented": jti,
                "username": username,
                "fingerprint": fp,
                "superseded_by": row.superseded_by,
            },
            ip_address=client_ip or None,
        )
        return BreakglassAuthResult(ok=False)

    if not evaluate_breakglass_binding(db, request, jti=jti, username=username):
        return BreakglassAuthResult(ok=False)

    if not rotate:
        return BreakglassAuthResult(
            ok=True,
            payload=payload,
            username=username,
            jti=jti,
            chain_id=chain_id,
        )

    # Re-load after possible audit commit inside binding (weak drift).
    row = db.query(BreakGlassSession).filter_by(jti=jti).first()
    if row is None or row.superseded_by or bool(row.chain_revoked) or bool(row.revoked):
        return BreakglassAuthResult(ok=False)

    new_token, new_row = rotate_breakglass_session(db, row, payload, secret)
    return BreakglassAuthResult(
        ok=True,
        payload=payload,
        set_cookie=new_token,
        username=username,
        jti=new_row.jti,
        chain_id=chain_id,
    )


def list_breakglass_sessions(
    db: Session,
    *,
    include_expired: bool = True,
    limit: int = 100,
) -> list[BreakGlassSession]:
    """Raw rows newest first (prefer ``list_breakglass_chains`` for admin UI)."""
    now = utcnow()
    q = db.query(BreakGlassSession).order_by(BreakGlassSession.issued_at.desc())
    if not include_expired:
        q = q.filter(
            BreakGlassSession.expires_at > now,
            BreakGlassSession.revoked.is_(False),
            BreakGlassSession.chain_revoked.is_(False),
        )
    return q.limit(max(1, min(limit, 500))).all()


def list_breakglass_chains(
    db: Session,
    *,
    include_expired: bool = True,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """One entry per rotation chain for admin listing."""
    now = utcnow()
    rows = (
        db.query(BreakGlassSession)
        .order_by(BreakGlassSession.issued_at.asc())
        .all()
    )
    by_chain: dict[str, list[BreakGlassSession]] = {}
    for row in rows:
        cid = (row.chain_id or row.jti or "").strip() or row.jti
        by_chain.setdefault(cid, []).append(row)

    chains: list[dict[str, Any]] = []
    for chain_id, members in by_chain.items():
        first = members[0]
        tip = next((m for m in reversed(members) if not m.superseded_by), members[-1])
        max_exp = max(
            (
                m.expires_at
                if m.expires_at.tzinfo
                else m.expires_at.replace(tzinfo=timezone.utc)
            )
            for m in members
            if m.expires_at is not None
        )
        chain_revoked = any(bool(m.chain_revoked) for m in members)
        expired = max_exp <= now
        if not include_expired and (expired or chain_revoked):
            continue
        if chain_revoked:
            status = "chain_revoked"
        elif expired:
            status = "expired"
        else:
            status = "active"
        chains.append(
            {
                "chain_id": chain_id,
                "username": tip.username or first.username,
                "rotation_count": max(0, len(members) - 1),
                "jti_current": tip.jti,
                "issued_at": first.issued_at.isoformat() if first.issued_at else None,
                "expires_at": max_exp.isoformat() if max_exp else None,
                "status": status,
                "active": status == "active",
                "chain_revoked": chain_revoked,
                "member_count": len(members),
            }
        )

    chains.sort(
        key=lambda c: c.get("issued_at") or "",
        reverse=True,
    )
    return chains[: max(1, min(limit, 500))]


def purge_expired_breakglass_sessions(
    db: Session,
    *,
    retention_days: int = BREAKGLASS_SESSION_RETENTION_DAYS,
) -> int:
    """
    Purge whole chains whose newest ``expires_at`` is older than retention.

    Never leaves orphan rows from a partially purged chain.
    """
    cutoff = utcnow() - timedelta(days=max(0, retention_days))
    rows = db.query(BreakGlassSession).all()
    by_chain: dict[str, list[BreakGlassSession]] = {}
    for row in rows:
        cid = (row.chain_id or row.jti or "").strip() or row.jti
        by_chain.setdefault(cid, []).append(row)

    to_delete: list[BreakGlassSession] = []
    for members in by_chain.values():
        max_exp = max(
            (
                m.expires_at
                if m.expires_at.tzinfo
                else m.expires_at.replace(tzinfo=timezone.utc)
            )
            for m in members
            if m.expires_at is not None
        )
        if max_exp < cutoff:
            to_delete.extend(members)

    for row in to_delete:
        db.delete(row)
    if to_delete:
        db.commit()
    return len(to_delete)


def decode_breakglass_token(cookie_value: str, secret: str) -> dict[str, Any] | None:
    """Decode and enforce absolute ``exp`` + idle timeout on ``last``."""
    if not secret or not cookie_value:
        return None
    try:
        payload = jwt.decode(cookie_value, secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "bg":
        return None
    if payload.get("exp") is None:
        # Absolute expiry is mandatory (reject legacy tokens without exp).
        return None
    last = payload.get("last")
    if last is None:
        # Legacy tokens without ``last``: treat iat as last activity.
        iat = payload.get("iat")
        if iat is None:
            return None
        last = int(iat) if not isinstance(iat, datetime) else int(iat.timestamp())
    else:
        last = int(last)
    now_ts = int(datetime.now(timezone.utc).timestamp())
    if now_ts - last > IDLE_TIMEOUT_SECONDS:
        return None
    return payload


def _jti_allowed(payload: dict[str, Any], db: Session | None) -> bool:
    jti = payload.get("jti")
    if not jti or not isinstance(jti, str):
        return False
    if db is not None and is_breakglass_jti_revoked(db, jti):
        return False
    return True


def validate_breakglass_cookie(
    cookie_value: str,
    secret: str | None = None,
    db: Session | None = None,
    *,
    settings: Settings | None = None,
) -> bool:
    """
    Validate break-glass JWT (absolute exp + idle + jti denylist).

    Pass ``settings=`` to use resolved signing secret + transition secrets
    (UI / legacy). Pass ``secret=`` for explicit single-key validation (unit tests).
    """
    if settings is not None:
        payload, _used_fallback = decode_breakglass_token_with_fallback(
            cookie_value, settings, db=db
        )
        if payload is None:
            return False
        return _jti_allowed(payload, db)
    if not secret:
        return False
    payload = decode_breakglass_token(cookie_value, secret)
    if payload is None:
        return False
    return _jti_allowed(payload, db)


def maybe_refresh_breakglass_cookie(
    cookie_value: str,
    secret: str | None = None,
    db: Session | None = None,
    *,
    settings: Settings | None = None,
) -> str | None:
    """
    If the token is valid and idle window should slide, return a new JWT.
    Absolute ``exp`` and ``jti`` are preserved from the original token.

    When ``settings`` is provided, validation may use transition secrets, but
    the refreshed token is always signed with ``resolve_breakglass_signing_secret``
    (upgrades old cookies to the active dedicated HMAC key).
    """
    if settings is not None:
        payload, _used_fallback = decode_breakglass_token_with_fallback(
            cookie_value, settings, db=db
        )
        if payload is None or not _jti_allowed(payload, db):
            return None
        sign_secret = resolve_breakglass_signing_secret(settings, db=db)
    else:
        if not secret or not validate_breakglass_cookie(cookie_value, secret, db=db):
            return None
        payload = decode_breakglass_token(cookie_value, secret)
        if payload is None:
            return None
        sign_secret = secret

    jti = payload.get("jti")
    if not jti:
        return None
    now = datetime.now(timezone.utc)
    now_ts = int(now.timestamp())
    last = int(payload.get("last") or now_ts)
    if now_ts - last < _IDLE_TOUCH_MIN_SECONDS:
        return None
    exp_dt = _aware_exp(payload.get("exp"))
    if exp_dt is None or now >= exp_dt:
        return None
    refreshed = {
        "sub": payload.get("sub"),
        "iat": payload.get("iat"),
        "exp": exp_dt,
        "last": now_ts,
        "type": "bg",
        "jti": jti,
    }
    return jwt.encode(refreshed, sign_secret, algorithm="HS256")


def set_breakglass_cookie(
    response: Response,
    token: str,
    settings: Settings,
    *,
    max_age: int | None = None,
) -> None:
    # Host-only cookie (no Domain=) so it stays on the portal host and works in tests.
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=max_age if max_age is not None else COOKIE_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="lax",
    )


def _client_ip(request: Request) -> str:
    return client_ip_from_request(request)


def _serialize_session(row: BreakGlassSession) -> dict[str, Any]:
    now = utcnow()
    exp = row.expires_at
    if exp is not None and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    active = (
        (not row.revoked)
        and (not bool(row.chain_revoked))
        and (exp is None or exp > now)
        and not row.superseded_by
    )
    return {
        "jti": row.jti,
        "chain_id": row.chain_id or row.jti,
        "username": row.username,
        "issued_at": row.issued_at.isoformat() if row.issued_at else None,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "revoked": bool(row.revoked),
        "chain_revoked": bool(row.chain_revoked),
        "superseded_by": row.superseded_by,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        "revoked_by": row.revoked_by,
        "revoked_reason": row.revoked_reason,
        "active": active,
    }


@router.post("/login")
async def breakglass_login(
    body: BreakglassLoginBody,
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    # Need env secret, UI secret, vault token (legacy), or ephemeral will be used.
    from app.breakglass_secret_service import get_ui_breakglass_secret

    if not (
        (settings.breakglass_jwt_secret or "").strip()
        or get_ui_breakglass_secret(db, settings)
        or (settings.vault_portal_internal_token or "").strip()
    ):
        raise HTTPException(
            status_code=503,
            detail="Break-glass JWT secret not configured (BREAKGLASS_JWT_SECRET)",
        )

    # Defense in depth (F-01/F-06): same LAN gate as Nginx allowlist / HTML /auth/login.
    from app.auth import is_rfc1918

    client_ip = _client_ip(request)
    if not is_rfc1918(client_ip, settings.rfc1918_cidrs):
        log_action(
            db,
            actor=body.username,
            action="breakglass.login_denied_non_lan",
            details={"reason": "client_ip_not_rfc1918", "via": "api"},
            ip_address=client_ip or None,
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    if not verify_breakglass_password(db, body.username, body.password):
        log_action(
            db,
            actor=body.username,
            action="breakglass.login_failed",
            ip_address=client_ip or None,
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    signing = resolve_breakglass_signing_secret(settings, db=db)
    token, jti = issue_breakglass_token(
        db, body.username, signing, request=request
    )
    db.commit()
    set_breakglass_cookie(response, token, settings)
    log_action(
        db,
        actor=body.username,
        action="breakglass.login",
        details={"jti": jti},
        ip_address=_client_ip(request),
    )
    return {"status": "ok", "username": body.username}


@router.post("/logout")
async def breakglass_logout(
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    username = "unknown"
    bg_cookie = request.cookies.get(COOKIE_NAME)
    if bg_cookie:
        payload, _fb = decode_breakglass_token_with_fallback(bg_cookie, settings, db=db)
        if payload:
            username = payload.get("sub", "unknown")
            jti = payload.get("jti")
            if jti:
                try:
                    revoke_breakglass_jti(
                        db,
                        str(jti),
                        revoked_by=str(username),
                        reason="logout",
                    )
                    db.commit()
                except LookupError:
                    pass
        else:
            # Logout even if idle-expired: try decode without idle via transition secrets
            from app.breakglass_secret_service import get_ui_breakglass_previous_secret
            from app.breakglass_secret_service import get_ui_breakglass_secret

            candidates = [
                resolve_breakglass_signing_secret(settings, db=db),
                get_ui_breakglass_secret(db, settings) or "",
                get_ui_breakglass_previous_secret(db, settings) or "",
                _legacy_breakglass_hmac_secret(settings),
            ]
            seen: set[str] = set()
            for sec in candidates:
                if not sec or sec in seen:
                    continue
                seen.add(sec)
                try:
                    raw = jwt.decode(
                        bg_cookie,
                        sec,
                        algorithms=["HS256"],
                        options={"verify_exp": False},
                    )
                    if raw.get("type") != "bg":
                        continue
                    username = raw.get("sub", "unknown")
                    jti = raw.get("jti")
                    if jti:
                        try:
                            revoke_breakglass_jti(
                                db,
                                str(jti),
                                revoked_by=str(username),
                                reason="logout",
                            )
                            db.commit()
                        except LookupError:
                            pass
                    break
                except jwt.PyJWTError:
                    continue

    response.delete_cookie(key=COOKIE_NAME)
    log_action(
        db,
        actor=username,
        action="breakglass.logout",
        ip_address=_client_ip(request),
    )
    return {"status": "ok"}


@admin_router.get("/sessions")
def breakglass_sessions_list(
    db: Session = Depends(get_db),
    active_only: bool = False,
    limit: int = 100,
):
    """List break-glass sessions grouped by rotation chain for admin UI."""
    chains = list_breakglass_chains(
        db, include_expired=not active_only, limit=limit
    )
    return {
        "chains": chains,
        # Backward-compatible alias: one synthetic entry per chain (current jti).
        "sessions": [
            {
                "jti": c["jti_current"],
                "chain_id": c["chain_id"],
                "username": c["username"],
                "issued_at": c["issued_at"],
                "expires_at": c["expires_at"],
                "revoked": c["status"] == "chain_revoked",
                "chain_revoked": c["chain_revoked"],
                "rotation_count": c["rotation_count"],
                "status": c["status"],
                "active": c["active"],
            }
            for c in chains
        ],
        "retention_days": BREAKGLASS_SESSION_RETENTION_DAYS,
    }


@admin_router.post("/sessions/{jti}/revoke")
def breakglass_session_revoke(
    jti: str,
    request: Request,
    body: BreakglassRevokeBody | None = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """Revoke a break-glass JWT and cut its entire rotation chain."""
    # Router is mounted with Depends(require_admin); resolve actor for audit.
    from app.web.user_context import get_user_context

    admin = get_user_context(request, settings, db=db)
    if admin is None:
        raise HTTPException(status_code=403, detail="Admin access required")
    reason = (body.reason if body else None) or "manual"
    try:
        row = revoke_breakglass_jti(
            db,
            jti,
            revoked_by=admin.email or admin.username,
            reason=reason,
        )
        db.commit()
    except LookupError:
        raise HTTPException(status_code=404, detail="Break-glass session not found") from None

    log_action(
        db,
        actor=admin.email or admin.username,
        action="breakglass_session_revoked",
        target=row.username,
        details={
            "jti": row.jti,
            "chain_id": row.chain_id or row.jti,
            "username": row.username,
            "reason": row.revoked_reason,
            "chain_revoked": True,
        },
        ip_address=_client_ip(request),
    )
    return {
        "status": "ok",
        "jti": row.jti,
        "chain_id": row.chain_id or row.jti,
        "username": row.username,
        "revoked": True,
        "chain_revoked": True,
    }
