"""Verified liveness for the /sessions registry.

``ActiveSession`` rows only say "someone was seen". The status shown to admins
is instead derived from the store that actually authorises each session, so a
revoked, expired or idle-timed-out credential never shows as active:

- break-glass portal  → ``BreakGlassSession`` rotation chain (revoked / absolute
  ``exp`` / idle timeout measured from the chain tip, i.e. the JWT ``last``)
- native OIDC portal  → ``OidcSession`` jtis of the identity (revoked / ``exp``)
- oauth2-proxy portal → ``SsoSessionAnchor`` sightings (cookie accepted by
  oauth2-proxy on a recent auth_request); no server-side state beyond that
- driven app          → upstream probe (``session_verify``), persisted in
  ``last_verified_*``
- SSO app presence    → each subdomain auth_request grant, and the identity's
  portal credential (an app reached through the bastion dies with it)

All lookups are batched per snapshot: one query per credential store.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import ActiveSession, BreakGlassSession, OidcSession, SsoSessionAnchor

# A session counts as "online" when its credential is valid and it served an
# authenticated request this recently. Must stay above the heartbeat throttles
# (portal 30 s, app presence 60 s) so a busy user never flickers to idle.
ONLINE_WINDOW = timedelta(minutes=3)

# Presence-only app rows (SSO grant, no server-side app session): once no grant
# was seen for this long the "session" is over from the bastion's standpoint.
PRESENCE_IDLE_TTL = timedelta(hours=1)

# oauth2-proxy keeps no server-side state: an anchor sighting proves the cookie
# was accepted then. Past cookie_refresh the cookie may be dead without us knowing.
OAUTH2_PROOF_WINDOW = timedelta(hours=1)
OAUTH2_COOKIE_EXPIRE = timedelta(hours=12)

# Tolerance before declaring a break-glass chain idle-expired: a grace-window
# resync re-signs the tip with a fresher ``last`` than the tip's issued_at.
BREAKGLASS_IDLE_SLACK = timedelta(seconds=60)

VERDICT_VALID = "valid"
VERDICT_REVOKED = "revoked"
VERDICT_EXPIRED = "expired"
VERDICT_INVALID = "invalid"
VERDICT_UNKNOWN = "unknown"
ENDED_VERDICTS = frozenset({VERDICT_REVOKED, VERDICT_EXPIRED})

STATE_ONLINE = "online"
STATE_IDLE = "idle"
STATE_UNVERIFIED = "unverified"
STATE_INVALID = "invalid"
STATE_ISOLATED = "isolated"
STATE_ENDED = "ended"

# Group headline: the "most alive" member wins.
STATE_PRIORITY = {
    STATE_ONLINE: 0,
    STATE_IDLE: 1,
    STATE_UNVERIFIED: 2,
    STATE_INVALID: 3,
    STATE_ISOLATED: 4,
}

METHOD_BREAKGLASS = "breakglass_jti"
METHOD_OIDC = "oidc_jti"
METHOD_OAUTH2 = "oauth2_proxy"
METHOD_UPSTREAM = "upstream_probe"
METHOD_SSO_GRANT = "sso_grant"
METHOD_TRAFFIC = "traffic"
METHOD_NONE = "none"
# Verified straight from a bastion-owned store on every snapshot.
CONTINUOUS_METHODS = frozenset({METHOD_BREAKGLASS, METHOD_OIDC})

_BREAKGLASS = "BREAKGLASS"


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _latest(*values: datetime | None) -> datetime | None:
    present = [v for v in (_aware(x) for x in values) if v is not None]
    return max(present) if present else None


def identity_keys(*values: str | None) -> set[str]:
    """Lowercased identity labels plus e-mail local parts (registry ↔ jti username)."""
    out: set[str] = set()
    for value in values:
        v = (value or "").strip().lower()
        if not v:
            continue
        out.add(v)
        if "@" in v:
            local = v.split("@", 1)[0]
            if local:
                out.add(local)
    return out


@dataclass(frozen=True)
class Proof:
    """What the authorising store says about one session, and when it said it."""

    verdict: str
    method: str
    checked_at: datetime | None = None
    expires_at: datetime | None = None
    idle_expires_at: datetime | None = None
    activity_at: datetime | None = None
    credentials: int = 0
    reason: str | None = None

    @property
    def ended(self) -> bool:
        return self.verdict in ENDED_VERDICTS


@dataclass
class _Chain:
    members: list[BreakGlassSession] = field(default_factory=list)


def _is_breakglass_row(row: ActiveSession) -> bool:
    if (row.protocol or "").upper() == _BREAKGLASS:
        return True
    details = row.details if isinstance(row.details, dict) else {}
    return (details.get("auth_source") or "").strip().lower() == "breakglass"


def _row_keys(row: ActiveSession) -> set[str]:
    return identity_keys(row.user_email, row.username)


def _chain_key(member: BreakGlassSession) -> str:
    return (member.chain_id or "").strip() or member.jti


def _oidc_end(s: OidcSession) -> datetime | None:
    exp = _aware(s.expires_at)
    if s.revoked:
        revoked_at = _aware(s.revoked_at)
        if revoked_at is not None and (exp is None or revoked_at < exp):
            return revoked_at
    return exp


class RegistryVerifier:
    """Batch-verify registry rows against their credential stores (one snapshot)."""

    def __init__(self, db: Session, rows: Iterable[ActiveSession], *, now: datetime):
        self.db = db
        self.now = _aware(now)
        self.rows = [r for r in rows if r is not None]
        self._oidc: dict[str, list[OidcSession]] = defaultdict(list)
        self._bg_by_user: dict[str, list[_Chain]] = defaultdict(list)
        self._bg_by_key: dict[str, _Chain] = {}
        self._anchor_seen: dict[str, datetime] = {}
        self._load()

    # ── prefetch ────────────────────────────────────────────────────────

    def _oldest_start(self, rows: list[ActiveSession]) -> datetime:
        starts = [_aware(r.started_at) for r in rows if r.started_at is not None]
        return min(starts) if starts else self.now - OAUTH2_COOKIE_EXPIRE

    def _load(self) -> None:
        if not self.rows:
            return
        bg_rows = [r for r in self.rows if _is_breakglass_row(r)]
        sso_rows = [r for r in self.rows if not _is_breakglass_row(r)]
        if sso_rows:
            self._load_oidc(sso_rows)
            self._load_anchors(sso_rows)
        if bg_rows:
            self._load_breakglass(bg_rows)

    def _load_oidc(self, rows: list[ActiveSession]) -> None:
        names: set[str] = set()
        for r in rows:
            names |= _row_keys(r)
        if not names:
            return
        # A jti that expired before the oldest row started cannot overlap any of them.
        found = (
            self.db.query(OidcSession)
            .filter(
                func.lower(func.trim(OidcSession.username)).in_(sorted(names)),
                OidcSession.expires_at >= self._oldest_start(rows),
            )
            .all()
        )
        for s in found:
            for key in identity_keys(s.username):
                self._oidc[key].append(s)

    def _load_anchors(self, rows: list[ActiveSession]) -> None:
        names: set[str] = set()
        for r in rows:
            if r.kind == "user":
                names |= _row_keys(r)
        if not names:
            return
        found = (
            self.db.query(
                func.lower(func.trim(SsoSessionAnchor.username)),
                func.max(SsoSessionAnchor.last_seen),
            )
            .filter(func.lower(func.trim(SsoSessionAnchor.username)).in_(sorted(names)))
            .group_by(func.lower(func.trim(SsoSessionAnchor.username)))
            .all()
        )
        for name, seen in found:
            seen = _aware(seen)
            if name and seen is not None:
                self._anchor_seen[name] = seen

    def _load_breakglass(self, rows: list[ActiveSession]) -> None:
        users: set[str] = set()
        for r in rows:
            uname = (r.username or "").strip()
            if uname:
                users.add(uname)
            email = (r.user_email or "").strip()
            if "@" in email:
                users.add(email.split("@", 1)[0])
        if not users:
            return
        found = (
            self.db.query(BreakGlassSession)
            .filter(
                BreakGlassSession.username.in_(sorted(users)),
                BreakGlassSession.expires_at >= self._oldest_start(rows),
            )
            .all()
        )
        for member in found:
            key = _chain_key(member)
            chain = self._bg_by_key.get(key)
            if chain is None:
                chain = _Chain()
                self._bg_by_key[key] = chain
                self._bg_by_user[(member.username or "").strip().lower()].append(chain)
            chain.members.append(member)
            # Registry rows may hold any jti of the chain (stamped at the last page load).
            self._bg_by_key.setdefault(member.jti, chain)

    # ── per-family proofs ───────────────────────────────────────────────

    def _chain_proof(self, chain: _Chain) -> tuple[Proof, datetime | None]:
        """(proof, end time) for one break-glass rotation chain."""
        members = chain.members
        tips = [m for m in members if not m.superseded_by] or members
        tip = max(tips, key=lambda m: _aware(m.issued_at) or self.now)
        revoked = [m for m in members if m.revoked or m.chain_revoked]
        if revoked:
            targeted = next((m for m in revoked if m.revoked), revoked[0])
            ended_at = _latest(*(m.revoked_at for m in revoked)) or _aware(
                tip.issued_at
            )
            return (
                Proof(
                    VERDICT_REVOKED,
                    METHOD_BREAKGLASS,
                    checked_at=self.now,
                    reason=(targeted.revoked_reason or "revoked"),
                ),
                ended_at,
            )
        from app.auth.breakglass import IDLE_TIMEOUT_SECONDS

        issued = _aware(tip.issued_at) or self.now
        absolute = _aware(tip.expires_at)
        idle_deadline = issued + timedelta(seconds=IDLE_TIMEOUT_SECONDS)
        if absolute is not None and self.now >= absolute:
            return (
                Proof(
                    VERDICT_EXPIRED,
                    METHOD_BREAKGLASS,
                    checked_at=self.now,
                    expires_at=absolute,
                    reason="absolute_ttl",
                ),
                absolute,
            )
        if self.now >= idle_deadline + BREAKGLASS_IDLE_SLACK:
            return (
                Proof(
                    VERDICT_EXPIRED,
                    METHOD_BREAKGLASS,
                    checked_at=self.now,
                    expires_at=absolute,
                    idle_expires_at=idle_deadline,
                    reason="idle_timeout",
                ),
                idle_deadline,
            )
        return (
            Proof(
                VERDICT_VALID,
                METHOD_BREAKGLASS,
                checked_at=self.now,
                expires_at=absolute,
                idle_expires_at=idle_deadline,
                activity_at=issued,
                credentials=1,
            ),
            None,
        )

    def _breakglass_proof(self, row: ActiveSession) -> Proof | None:
        details = row.details if isinstance(row.details, dict) else {}
        for key in (details.get("chain_id"), details.get("jti")):
            chain = self._bg_by_key.get((key or "").strip()) if key else None
            if chain is not None:
                return self._chain_proof(chain)[0]
        # App presence rows (no jti stamped): any chain of that admin alive
        # during the row's lifetime decides.
        names = identity_keys(row.username)
        email = (row.user_email or "").strip().lower()
        if "@" in email:
            names.add(email.split("@", 1)[0])
        chains: list[_Chain] = []
        for name in names:
            chains.extend(self._bg_by_user.get(name, []))
        return self._merge_overlapping(
            [self._chain_proof(c) for c in chains], started=_aware(row.started_at)
        )

    def _merge_overlapping(
        self, proofs: list[tuple[Proof, datetime | None]], *, started: datetime | None
    ) -> Proof | None:
        """Credentials alive at some point of the row's life decide its fate."""
        relevant = [
            (p, end) for p, end in proofs if end is None or started is None or end >= started
        ]
        if not relevant:
            return None
        live = [p for p, _ in relevant if p.verdict == VERDICT_VALID]
        if live:
            return Proof(
                VERDICT_VALID,
                live[0].method,
                checked_at=self.now,
                expires_at=_latest(*(p.expires_at for p in live)),
                idle_expires_at=_latest(*(p.idle_expires_at for p in live)),
                activity_at=_latest(*(p.activity_at for p in live)),
                credentials=sum(max(1, p.credentials) for p in live),
            )
        last = max(relevant, key=lambda pe: pe[1] or self.now)
        return last[0]

    def _oidc_proof(self, row: ActiveSession) -> Proof | None:
        realm = (row.realm or "").strip()
        seen: dict[str, OidcSession] = {}
        for key in _row_keys(row):
            for s in self._oidc.get(key, []):
                if realm and (s.realm or "").strip() and s.realm != realm:
                    continue
                seen[s.jti] = s
        if not seen:
            return None
        started = _aware(row.started_at)
        proofs: list[tuple[Proof, datetime | None]] = []
        for s in seen.values():
            exp = _aware(s.expires_at)
            if s.revoked:
                expired = (s.revoked_reason or "") == "expired"
                verdict = VERDICT_EXPIRED if expired else VERDICT_REVOKED
                proofs.append(
                    (
                        Proof(
                            verdict,
                            METHOD_OIDC,
                            checked_at=self.now,
                            expires_at=exp,
                            reason=s.revoked_reason or "revoked",
                        ),
                        _oidc_end(s),
                    )
                )
            elif exp is not None and exp <= self.now:
                proofs.append(
                    (
                        Proof(
                            VERDICT_EXPIRED,
                            METHOD_OIDC,
                            checked_at=self.now,
                            expires_at=exp,
                            reason="absolute_ttl",
                        ),
                        exp,
                    )
                )
            else:
                proofs.append(
                    (
                        Proof(
                            VERDICT_VALID,
                            METHOD_OIDC,
                            checked_at=self.now,
                            expires_at=exp,
                            credentials=1,
                        ),
                        None,
                    )
                )
        return self._merge_overlapping(proofs, started=started)

    def _oauth2_proof(self, row: ActiveSession) -> Proof:
        seen = _latest(*(self._anchor_seen.get(k) for k in _row_keys(row)))
        started = _aware(row.started_at) or self.now
        expires = started + OAUTH2_COOKIE_EXPIRE
        if seen is not None and self.now - seen <= OAUTH2_PROOF_WINDOW:
            return Proof(
                VERDICT_VALID,
                METHOD_OAUTH2,
                checked_at=seen,
                expires_at=expires,
                activity_at=seen,
                credentials=1,
            )
        return Proof(
            VERDICT_UNKNOWN,
            METHOD_OAUTH2 if seen is not None else METHOD_NONE,
            checked_at=seen,
            expires_at=expires,
            reason="no_recent_proof" if seen is not None else "no_server_state",
        )

    def _portal_proof(self, row: ActiveSession) -> Proof:
        if _is_breakglass_row(row):
            return self._breakglass_proof(row) or Proof(
                VERDICT_UNKNOWN, METHOD_NONE, reason="jti_not_found"
            )
        return self._oidc_proof(row) or self._oauth2_proof(row)

    def _parent_proof(self, row: ActiveSession) -> Proof | None:
        """Portal credential of the identity that reached this app (if known)."""
        if _is_breakglass_row(row):
            return self._breakglass_proof(row)
        return self._oidc_proof(row)

    def _app_proof(self, row: ActiveSession) -> Proof:
        details = row.details if isinstance(row.details, dict) else {}
        parent = self._parent_proof(row)
        if parent is not None and parent.ended:
            return Proof(
                parent.verdict,
                parent.method,
                checked_at=self.now,
                reason="portal_session_ended",
            )
        parent_exp = parent.expires_at if parent is not None else None
        last_seen = _aware(row.last_seen_at)
        if details.get("verifiable"):
            status = (row.last_verified_status or "").strip().lower()
            checked = _aware(row.last_verified_at)
            if status == "active":
                return Proof(
                    VERDICT_VALID,
                    METHOD_UPSTREAM,
                    checked_at=checked,
                    expires_at=parent_exp,
                    credentials=1,
                )
            if status == "invalid":
                return Proof(
                    VERDICT_INVALID,
                    METHOD_UPSTREAM,
                    checked_at=checked,
                    reason="upstream_rejected",
                )
            return Proof(
                VERDICT_UNKNOWN,
                METHOD_UPSTREAM,
                checked_at=checked,
                expires_at=parent_exp,
                reason="probe_pending" if checked is None else "probe_inconclusive",
            )
        presence_only = bool(details.get("presence_only"))
        if (
            presence_only
            and last_seen is not None
            and self.now - last_seen > PRESENCE_IDLE_TTL
        ):
            return Proof(
                VERDICT_EXPIRED,
                METHOD_SSO_GRANT,
                checked_at=last_seen,
                reason="presence_idle",
            )
        # Each subdomain auth_request grant is an authenticated check at that time.
        return Proof(
            VERDICT_VALID,
            METHOD_SSO_GRANT,
            checked_at=last_seen,
            expires_at=parent_exp,
            activity_at=last_seen,
            credentials=1,
        )

    # ── public ──────────────────────────────────────────────────────────

    def proof(self, row: ActiveSession) -> Proof:
        if row.kind == "user":
            return self._portal_proof(row)
        return self._app_proof(row)


def classify(row: ActiveSession, proof: Proof, *, now: datetime) -> tuple[str, datetime | None]:
    """(state, last authenticated activity) for one row."""
    now = _aware(now)
    activity = _latest(row.last_seen_at, proof.activity_at)
    if (row.status or "") == "isolated":
        return STATE_ISOLATED, activity
    if proof.ended:
        return STATE_ENDED, activity
    if proof.verdict == VERDICT_INVALID:
        return STATE_INVALID, activity
    recent = activity is not None and now - activity <= ONLINE_WINDOW
    if proof.verdict == VERDICT_VALID:
        return (STATE_ONLINE if recent else STATE_IDLE), activity
    # Registry touches only happen on authenticated requests: a fresh one is a
    # proof by itself, even where the credential store cannot be read.
    if recent and row.kind == "user":
        return STATE_ONLINE, activity
    return STATE_UNVERIFIED, activity


def proof_payload(proof: Proof, *, state: str) -> dict[str, Any]:
    def iso(value: datetime | None) -> str | None:
        value = _aware(value)
        return value.isoformat() if value else None

    method = proof.method
    if (
        state == STATE_ONLINE
        and proof.verdict == VERDICT_UNKNOWN
        and method in (METHOD_NONE, METHOD_OAUTH2)
    ):
        method = METHOD_TRAFFIC
    # Store-backed checks are re-run on every snapshot: a "checked at <now>"
    # stamp would only churn the live feed. Say "continuous" instead.
    continuous = method in CONTINUOUS_METHODS
    return {
        "verdict": proof.verdict,
        "method": method,
        "continuous": continuous,
        "checked_at": None if continuous else iso(proof.checked_at),
        "expires_at": iso(proof.expires_at),
        "idle_expires_at": iso(proof.idle_expires_at),
        "credentials": proof.credentials,
        "reason": proof.reason,
    }
