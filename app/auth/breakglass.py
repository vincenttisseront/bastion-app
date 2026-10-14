"""Break-glass login, JWT cookie, session jti denylist, and admin routes."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.audit import log_action
from app.auth.breakglass_store import breakglass_account_exists, verify_breakglass_password
from app.database import get_db
from app.auth.jwt_audience import (
    DEFAULT_BREAKGLASS_JWT_AUDIENCE,
    jwt_audience_matches,
    resolve_breakglass_jwt_audience,
)
from app.models import BreakGlassSession, utcnow
from app.request_client_ip import client_ip_from_request
from app.session_cookies import clear_portal_cookie, set_portal_cookie
from app.sso_settings import Settings, get_settings
from app.web.openapi_responses import RESP_401, RESP_403, RESP_404

if TYPE_CHECKING:
    from app.auth.breakglass_secret_service import SigningSource

logger = logging.getLogger(__name__)

COOKIE_NAME = "bg_session"
# Absolute TTL — PROPOSED / documented in architecture (8h). Validated on every decode.
COOKIE_MAX_AGE = 8 * 3600
# Idle timeout — PROPOSED for admin break-glass (stricter than SSO). Sliding via ``last`` claim.
IDLE_TIMEOUT_SECONDS = 30 * 60
# Browser responses rotate the jti at most this often: a page fires many
# requests, and a rotation per request multiplies rows and replay false positives.
ROTATION_MIN_INTERVAL_SECONDS = 60
# Keep revoked/expired session rows for audit before purge (documented, not arbitrary).
BREAKGLASS_SESSION_RETENTION_DAYS = 7
# Grace window after rotation: old cookie still accepted briefly (parallel requests / race).
GRACE_WINDOW_SECONDS = 5
# TTL when the session registry is unreachable: such a token has no row, so it
# cannot be revoked. Short enough to bound that, long enough to fix the outage.
DEGRADED_TOKEN_TTL_SEC = 30 * 60

# Process-lifetime secret when BREAKGLASS_JWT_SECRET is unset (dev / first boot).
_EPHEMERAL_JWT_SECRET: str | None = None

# Public: login / logout (cannot require an existing portal session).
router = APIRouter(prefix="/api/admin/breakglass", tags=["breakglass"])
# Admin list/revoke — ``require_admin`` attached in ``main`` (avoids circular import
# with ``user_context`` which imports this module for cookie validation).
admin_router = APIRouter(prefix="/api/admin/breakglass", tags=["breakglass"])


class BreakglassLoginBody(BaseModel):
    username: str = Field(max_length=256)
    password: str = Field(max_length=512)


class BreakglassRevokeBody(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


@dataclass(frozen=True, slots=True, kw_only=True)
class BreakglassAuthResult:
    """Outcome of protected-request processing (rotation / replay / grace)."""

    ok: bool
    payload: dict[str, Any] | None = None
    set_cookie: str | None = None
    username: str = ""
    jti: str = ""
    chain_id: str | None = None


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
    1. ``BREAKGLASS_JWT_SECRET`` (env)
    2. UI-generated secret in ``portal_settings`` (if env absent)
    3. Legacy ``VAULT_PORTAL_INTERNAL_TOKEN``
    4. Process-lifetime ephemeral (dev / last resort)

    Returns ``(secret, source)`` where source is env|ui|legacy|ephemeral.
    """
    from app.auth.breakglass_secret_service import get_ui_breakglass_secret

    def _from_ui_or_cache() -> tuple[str, SigningSource] | None:
        ui = get_ui_breakglass_secret(db, settings)
        if ui:
            return ui, "ui"
        from app.runtime_secrets_service import get_cached_breakglass_secret

        cached = get_cached_breakglass_secret()
        if cached:
            return cached, "ui"
        return None

    dedicated = (settings.breakglass_jwt_secret or "").strip()
    if dedicated:
        return dedicated, "env"

    found = _from_ui_or_cache()
    if found:
        return found

    # Lifespan may have skipped ensure (race / decrypt failure). Seed once, then retry.
    if db is not None:
        try:
            from app.runtime_secrets_service import ensure_portal_runtime_secrets

            ensure_portal_runtime_secrets(db, settings, actor="breakglass_resolve")
        except Exception:
            logger.exception(
                "breakglass: ensure_portal_runtime_secrets failed during resolve"
            )
        found = _from_ui_or_cache()
        if found:
            return found

    if settings.is_production:
        raise RuntimeError(
            "BREAKGLASS_JWT_SECRET is required in production "
            "(set env or seed portal_settings via migrate — "
            "no VAULT_PORTAL_INTERNAL_TOKEN fallback)"
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
            "BREAKGLASS_JWT_SECRET unset and no UI secret — using ephemeral process "
            "secret; set BREAKGLASS_JWT_SECRET via env or generate from Admin → Sécurité"
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
    from app.auth.breakglass_secret_service import (
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
    # Production validator forces the flag off: the vault token is never accepted there.
    if settings.breakglass_jwt_secret_fallback_enabled:
        add(_legacy_breakglass_hmac_secret(settings), "legacy")
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
    expected_aud = resolve_breakglass_jwt_audience(settings)
    strict_aud = settings.breakglass_jwt_audience_strict
    for secret, label in _validation_secrets(settings, db=db):
        payload = decode_breakglass_token(
            cookie_value,
            secret,
            audience=expected_aud,
            audience_strict=strict_aud,
        )
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
    ttl_seconds: int = COOKIE_MAX_AGE,
    audience: str | None = None,
) -> str:
    """Build a break-glass JWT. Always includes a unique ``jti`` claim."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(seconds=ttl_seconds),
        "last": int(now.timestamp()),
        "type": "bg",
        "jti": jti or str(uuid4()),
        "aud": (audience or DEFAULT_BREAKGLASS_JWT_AUDIENCE).strip(),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def registry_unavailable(exc: Exception, db: Session, *, stage: str) -> None:
    """Record that the session registry could not be reached, and carry on.

    The registry lives in the hot store; refusing here would remove the only
    way in that remains when the hot store is what needs repairing. Nothing is
    audited on this path either — ``audit_logs`` is a hot table too — so the
    application log is the sole trace.
    """
    logger.warning(
        "breakglass: session registry unavailable at %s, degrading — %s", stage, exc
    )
    try:
        db.rollback()
    except SQLAlchemyError:
        logger.exception("breakglass: rollback failed after registry outage")


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
    audience: str | None = None,
) -> tuple[str, str]:
    """Create JWT + BreakGlassSession row. Returns ``(token, jti)``.

    ``audience`` must be ``resolve_breakglass_jwt_audience(settings)`` in app
    code, otherwise strict audience validation rejects the issued token.
    """
    jti = str(uuid4())
    issued_at = datetime.now(timezone.utc)
    token = create_breakglass_token(username, secret, jti=jti, audience=audience)
    expires_at = issued_at + timedelta(seconds=COOKIE_MAX_AGE)
    try:
        row = register_breakglass_session(
            db,
            jti=jti,
            username=username,
            expires_at=expires_at,
            issued_at=issued_at,
            chain_id=jti,
        )
        if request is not None:
            from app.security.session_binding_service import (
                apply_breakglass_login_anchor,
            )

            apply_breakglass_login_anchor(db, row, request)
    except SQLAlchemyError as exc:
        registry_unavailable(exc, db, stage="issue")
        # An unregistered jti cannot be revoked (see resolve_breakglass_request),
        # so the degraded token is short-lived: re-login rechecks the password.
        return (
            create_breakglass_token(
                username,
                secret,
                jti=jti,
                ttl_seconds=DEGRADED_TOKEN_TTL_SEC,
                audience=audience,
            ),
            jti,
        )
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
    return (now - row.superseded_at).total_seconds() <= GRACE_WINDOW_SECONDS


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
    touched = (
        db.query(BreakGlassSession)
        .filter(BreakGlassSession.chain_id == chain_id)
        .update({BreakGlassSession.chain_revoked: True}, synchronize_session="fetch")
    )
    db.flush()
    return touched


def is_breakglass_jti_revoked(db: Session, jti: str) -> bool:
    """
    True if this jti must not authenticate.

    Covers explicit admin revoke, whole-chain cut, and superseded cookies outside
    the grace window. Tokens with no registry row keep prior behaviour (not blocked
    solely by missing row — unit tests without register still work).
    """
    if not jti:
        return True
    try:
        row = db.query(BreakGlassSession).filter_by(jti=jti).first()
    except SQLAlchemyError as exc:
        # Consulted on every protected request. An unreachable registry cannot
        # answer "revoked", and treating silence as revocation would log the
        # admin out of the interface needed to bring the hot store back.
        registry_unavailable(exc, db, stage="revocation_check")
        return False
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
    aud_raw = payload.get("aud")
    aud = (
        str(aud_raw).strip()
        if isinstance(aud_raw, str) and aud_raw.strip()
        else DEFAULT_BREAKGLASS_JWT_AUDIENCE
    )
    claims = {
        "sub": payload.get("sub"),
        "iat": payload.get("iat"),
        "exp": exp_dt,
        "last": last,
        "type": "bg",
        "jti": jti,
        "aud": aud,
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
    new_row = BreakGlassSession(
        jti=jti_next,
        chain_id=chain_id,
        username=row.username,
        issued_at=now,
        expires_at=row.expires_at,
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

    try:
        row = db.query(BreakGlassSession).filter_by(jti=jti).first()
    except SQLAlchemyError as exc:
        # Hot store down: the registry cannot answer. Locking the admin out here
        # would strand the one account able to repair it.
        registry_unavailable(exc, db, stage="verify")
        return BreakglassAuthResult(
            ok=True, payload=payload, username=username, jti=jti
        )
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

    try:
        bound = evaluate_breakglass_binding(db, request, jti=jti, username=username)
    except SQLAlchemyError as exc:
        # Binding anchors are hot rows too — an outage must not read as a
        # binding violation, which would look like a session hijack.
        registry_unavailable(exc, db, stage="binding")
        return BreakglassAuthResult(
            ok=True, payload=payload, username=username, jti=jti, chain_id=chain_id
        )
    if not bound:
        return BreakglassAuthResult(ok=False)

    if not rotate:
        return BreakglassAuthResult(
            ok=True,
            payload=payload,
            username=username,
            jti=jti,
            chain_id=chain_id,
        )

    try:
        # Re-load after possible audit commit inside binding (weak drift).
        row = db.query(BreakGlassSession).filter_by(jti=jti).first()
        if (
            row is None
            or row.superseded_by
            or bool(row.chain_revoked)
            or bool(row.revoked)
        ):
            return BreakglassAuthResult(ok=False)
        new_token, new_row = rotate_breakglass_session(db, row, payload, secret)
    except SQLAlchemyError as exc:
        # Keep the current cookie rather than cutting the chain: rotation is a
        # hardening measure, not the authorisation itself.
        registry_unavailable(exc, db, stage="rotate")
        return BreakglassAuthResult(
            ok=True, payload=payload, username=username, jti=jti, chain_id=chain_id
        )
    return BreakglassAuthResult(
        ok=True,
        payload=payload,
        set_cookie=new_token,
        username=username,
        jti=new_row.jti,
        chain_id=chain_id,
    )


def _chain_key():
    """SQL expression grouping rows by rotation chain (legacy rows: own jti)."""
    return func.coalesce(
        func.nullif(func.trim(BreakGlassSession.chain_id), ""),
        BreakGlassSession.jti,
    )


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
        entry = _breakglass_chain_entry(chain_id, members, now=now)
        if entry is None:
            continue
        if not include_expired and (
            entry["status"] in ("expired", "chain_revoked")
        ):
            continue
        chains.append(entry)
    chains.sort(key=lambda c: c.get("issued_at") or "", reverse=True)
    return chains[: max(1, min(limit, 500))]


def _breakglass_chain_entry(
    chain_id: str,
    members: list[BreakGlassSession],
    *,
    now,
) -> dict[str, Any] | None:
    if not members:
        return None
    first = members[0]
    tip = next((m for m in reversed(members) if not m.superseded_by), members[-1])
    dated = [m.expires_at for m in members if m.expires_at is not None]
    if not dated:
        return None
    max_exp = max(dated)
    chain_revoked = any(bool(m.chain_revoked) for m in members)
    expired = max_exp <= now
    if chain_revoked:
        status = "chain_revoked"
    elif expired:
        status = "expired"
    else:
        status = "active"
    return {
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


def purge_expired_breakglass_sessions(
    db: Session,
    *,
    retention_days: int = BREAKGLASS_SESSION_RETENTION_DAYS,
) -> int:
    """
    Purge whole chains whose newest ``expires_at`` is older than retention.

    Never leaves orphan rows from a partially purged chain. Chains whose rows
    all lack ``expires_at`` are kept (``max`` is NULL).
    """
    cutoff = utcnow() - timedelta(days=max(0, retention_days))
    chain_key = _chain_key()
    stale_chains = (
        select(chain_key)
        .group_by(chain_key)
        .having(func.max(BreakGlassSession.expires_at) < cutoff)
    )
    deleted = (
        db.query(BreakGlassSession)
        .filter(chain_key.in_(stale_chains))
        .delete(synchronize_session=False)
    )
    if deleted:
        db.commit()
    return deleted


def decode_breakglass_token(
    cookie_value: str,
    secret: str,
    *,
    audience: str | None = None,
    audience_strict: bool = False,
) -> dict[str, Any] | None:
    """Decode and enforce absolute ``exp`` + idle timeout on ``last``."""
    if not secret or not cookie_value:
        return None
    try:
        payload = jwt.decode(
            cookie_value,
            secret,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "bg":
        return None
    if audience is not None and not jwt_audience_matches(
        payload, audience, strict=audience_strict
    ):
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


def set_breakglass_cookie(
    response: Response,
    token: str,
    settings: Settings,
    *,
    max_age: int | None = None,
) -> None:
    """Set ``bg_session`` on the portal parent domain when possible.

    Subdomain auth_request (wikijs.*, webmail.*, …) must receive the cookie or
    break-glass admins only work on the portal host.
    """
    set_portal_cookie(
        response,
        COOKIE_NAME,
        token,
        max_age=max_age if max_age is not None else COOKIE_MAX_AGE,
        settings=settings,
    )


def clear_breakglass_cookie(
    response: Response,
    settings: Settings | None = None,
) -> None:
    """Clear ``bg_session`` (parent-domain and legacy host-only copies)."""
    clear_portal_cookie(response, COOKIE_NAME, settings)


def _decode_for_revocation(
    cookie_value: str, settings: Settings, db: Session
) -> dict[str, Any] | None:
    """Signature-only decode: logout must revoke idle-expired cookies too."""
    for secret, _label in _validation_secrets(settings, db=db):
        try:
            payload = jwt.decode(
                cookie_value,
                secret,
                algorithms=["HS256"],
                options={"verify_exp": False, "verify_aud": False},
            )
        except jwt.PyJWTError:
            continue
        if payload.get("type") == "bg":
            return payload
    return None


def revoke_breakglass_session_from_request(
    request: Request,
    db: Session,
    settings: Settings,
) -> str:
    """Revoke the current break-glass jti if present. Returns actor for audit."""
    bg_cookie = request.cookies.get(COOKIE_NAME)
    if not bg_cookie:
        return "unknown"
    payload = _decode_for_revocation(bg_cookie, settings, db)
    if payload is None:
        return "unknown"
    username = str(payload.get("sub") or "unknown")
    jti = payload.get("jti")
    if jti:
        try:
            revoke_breakglass_jti(db, str(jti), revoked_by=username, reason="logout")
            db.commit()
        except LookupError:
            pass
    return username


def _deny_breakglass_if_ip_blocked(db, username: str, client_ip: str | None, settings) -> None:
    from app.security.banning.engine import is_breakglass_ip_allowed

    if is_breakglass_ip_allowed(
        db, client_ip, rfc1918_cidrs=settings.rfc1918_cidrs
    ):
        return
    log_action(
        db,
        actor=username,
        action="breakglass.login_denied_non_lan",
        details={"reason": "breakglass_ip_not_allowed", "via": "api"},
        ip_address=client_ip or None,
    )
    raise HTTPException(status_code=403, detail="Forbidden")


@router.post("/login", responses=RESP_401 | RESP_403)
def breakglass_login(
    body: BreakglassLoginBody,
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    from app.security.banning.engine import (
        evaluate_login_attempt,
        record_successful_login,
    )

    try:
        signing = resolve_breakglass_signing_secret(settings, db=db)
    except RuntimeError:
        logger.exception("breakglass: signing secret unavailable")
        raise HTTPException(
            status_code=503,
            detail="Break-glass JWT secret not configured (BREAKGLASS_JWT_SECRET)",
        ) from None

    # Defense in depth: same LAN/Misc gate as HTML /auth/login.
    client_ip = client_ip_from_request(request)
    _deny_breakglass_if_ip_blocked(db, body.username, client_ip, settings)

    pre = evaluate_login_attempt(
        db, ip=client_ip, username=body.username, success=True
    )
    if not pre.allowed:
        raise HTTPException(status_code=403, detail="Forbidden")

    if not verify_breakglass_password(db, body.username, body.password):
        evaluate_login_attempt(
            db, ip=client_ip, username=body.username, success=False
        )
        # Same enriched details as the HTML form path — empty {} rows in
        # Admin → Logs were impossible to triage (probe vs real attempt).
        log_action(
            db,
            actor=body.username,
            action="breakglass.login_failed",
            details={
                "via": "api",
                "reason": (
                    "bad_password"
                    if breakglass_account_exists(db, body.username)
                    else "unknown_username"
                ),
                "user_agent": (request.headers.get("user-agent") or "")[:160] or None,
            },
            ip_address=client_ip or None,
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token, jti = issue_breakglass_token(
        db,
        body.username,
        signing,
        request=request,
        audience=resolve_breakglass_jwt_audience(settings),
    )
    db.commit()
    try:
        record_successful_login(db, ip=client_ip, username=body.username)
    except SQLAlchemyError:
        logger.exception("breakglass: could not reset login counters")
        db.rollback()
    set_breakglass_cookie(response, token, settings)
    log_action(
        db,
        actor=body.username,
        action="breakglass.login",
        details={"jti": jti},
        ip_address=client_ip or None,
    )
    return {"status": "ok", "username": body.username}


@router.post("/logout")
def breakglass_logout(
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    username = revoke_breakglass_session_from_request(request, db, settings)
    clear_breakglass_cookie(response, settings)
    log_action(
        db,
        actor=username,
        action="breakglass.logout",
        ip_address=client_ip_from_request(request) or None,
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


@admin_router.post("/sessions/{jti}/revoke", responses=RESP_403 | RESP_404)
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
        ip_address=client_ip_from_request(request) or None,
    )
    return {
        "status": "ok",
        "jti": row.jti,
        "chain_id": row.chain_id or row.jti,
        "username": row.username,
        "revoked": True,
        "chain_revoked": True,
    }
