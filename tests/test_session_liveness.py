"""Verified liveness of /sessions rows against the authorising credential stores."""

from __future__ import annotations

import json
from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import ActiveSession, BreakGlassSession, OidcSession, utcnow
from app.web import session_liveness as liveness
from app.web import sessions_service
from app.web.sessions_service import (
    close_registry_after_logout,
    get_active_sessions,
    touch_portal_heartbeat,
)

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
    "X-Portal-Realm-Slug": "default",
}

USER_HEADERS = {
    "X-Email": "alice@example.com",
    "X-Preferred-Username": "alice",
    "X-User-Id": "kc-user-alice",
    "X-Groups": "team-ops",
    "X-Portal-Realm-Slug": "example-corp",
}


def _row(
    db: Session,
    *,
    sid: str,
    kind: str = "user",
    email: str = "alice@example.com",
    username: str = "alice",
    realm: str = "example-corp",
    protocol: str = "OIDC",
    target: str = "portal",
    started_ago: timedelta = timedelta(minutes=30),
    seen_ago: timedelta = timedelta(seconds=5),
    details: dict | None = None,
) -> ActiveSession:
    now = utcnow()
    row = ActiveSession(
        id=sid,
        kind=kind,
        user_email=email,
        username=username,
        realm=realm,
        protocol=protocol,
        target=target,
        source_ip="203.0.113.7",
        status="active",
        started_at=now - started_ago,
        last_seen_at=now - seen_ago,
        details=details or {},
    )
    db.add(row)
    db.commit()
    return row


def _oidc_jti(
    db: Session,
    *,
    username: str = "alice",
    realm: str = "example-corp",
    issued_ago: timedelta = timedelta(minutes=40),
    ttl: timedelta = timedelta(hours=8),
    revoked: bool = False,
    reason: str | None = None,
) -> OidcSession:
    now = utcnow()
    jti = str(uuid4())
    row = OidcSession(
        jti=jti,
        sub=f"sub-{username}",
        username=username,
        realm=realm,
        issued_at=now - issued_ago,
        expires_at=now - issued_ago + ttl,
        revoked=revoked,
        revoked_at=now - timedelta(seconds=10) if revoked else None,
        revoked_by="alice" if revoked else None,
        revoked_reason=reason,
    )
    db.add(row)
    db.commit()
    return row


def _bg_chain(
    db: Session,
    *,
    username: str = "admin",
    issued_ago: timedelta = timedelta(minutes=2),
    ttl: timedelta = timedelta(hours=8),
) -> BreakGlassSession:
    now = utcnow()
    jti = str(uuid4())
    row = BreakGlassSession(
        jti=jti,
        chain_id=jti,
        username=username,
        issued_at=now - issued_ago,
        expires_at=now - issued_ago + ttl,
        revoked=False,
        chain_revoked=False,
    )
    db.add(row)
    db.commit()
    return row


def _bg_portal_row(db: Session, chain: BreakGlassSession, **kw) -> ActiveSession:
    return _row(
        db,
        sid="portal:admin@breakglass.local:",
        email="admin@breakglass.local",
        username="admin",
        realm="",
        protocol="BREAKGLASS",
        details={"jti": chain.jti, "chain_id": chain.chain_id, "auth_source": "breakglass"},
        **kw,
    )


def _by_id(db: Session) -> dict[str, dict]:
    return {s["id"]: s for s in get_active_sessions(db, locale="fr")}


# ── break-glass ─────────────────────────────────────────────────────────


def test_breakglass_valid_chain_is_online_with_deadlines(db_session: Session):
    chain = _bg_chain(db_session)
    _bg_portal_row(db_session, chain)
    s = _by_id(db_session)["portal:admin@breakglass.local:"]
    assert s["live_status"] == "online"
    v = s["verification"]
    assert v["method"] == "breakglass_jti"
    assert v["verdict"] == "valid"
    assert v["expires_at"] and v["idle_expires_at"]
    assert "Jeton break-glass valide" in v["summary"]


def test_breakglass_revoked_chain_disappears(db_session: Session):
    chain = _bg_chain(db_session)
    _bg_portal_row(db_session, chain)
    chain.revoked = True
    chain.chain_revoked = True
    chain.revoked_at = utcnow()
    chain.revoked_reason = "logout"
    db_session.commit()
    assert "portal:admin@breakglass.local:" not in _by_id(db_session)
    assert db_session.query(ActiveSession).count() == 0


def test_breakglass_idle_timeout_ends_session(db_session: Session):
    # Tip last rotated 45 min ago: the JWT ``last`` claim is past the 30 min idle.
    chain = _bg_chain(db_session, issued_ago=timedelta(minutes=45))
    _bg_portal_row(db_session, chain, seen_ago=timedelta(minutes=45))
    assert _by_id(db_session) == {}


def test_breakglass_follows_rotation_tip(db_session: Session):
    old = _bg_chain(db_session, issued_ago=timedelta(minutes=29))
    tip = BreakGlassSession(
        jti=str(uuid4()),
        chain_id=old.chain_id,
        username="admin",
        issued_at=utcnow() - timedelta(seconds=20),
        expires_at=old.expires_at,
        revoked=False,
        chain_revoked=False,
    )
    old.superseded_by = tip.jti
    old.superseded_at = tip.issued_at
    db_session.add(tip)
    db_session.commit()
    # Registry still holds the older jti (stamped at the previous page load).
    _bg_portal_row(db_session, old)
    s = _by_id(db_session)["portal:admin@breakglass.local:"]
    assert s["live_status"] == "online"
    idle = liveness._aware(sessions_service._parse_iso_dt(s["verification"]["idle_expires_at"]))
    assert idle > utcnow() + timedelta(minutes=29)


# ── native OIDC ─────────────────────────────────────────────────────────


def test_native_oidc_jti_verified(db_session: Session):
    _oidc_jti(db_session)
    _row(db_session, sid="portal:alice@example.com:example-corp")
    s = _by_id(db_session)["portal:alice@example.com:example-corp"]
    assert s["live_status"] == "online"
    assert s["verification"]["method"] == "oidc_jti"
    assert s["verification"]["credentials"] == 1


def test_native_oidc_idle_when_no_recent_activity(db_session: Session):
    _oidc_jti(db_session)
    _row(
        db_session,
        sid="portal:alice@example.com:example-corp",
        seen_ago=timedelta(minutes=12),
    )
    s = _by_id(db_session)["portal:alice@example.com:example-corp"]
    assert s["live_status"] == "idle"
    assert s["live_status_label"] == "INACTIF"


def test_native_oidc_revoked_jti_ends_session(db_session: Session):
    jti = _oidc_jti(db_session)
    _row(db_session, sid="portal:alice@example.com:example-corp")
    jti.revoked = True
    jti.revoked_at = utcnow()
    jti.revoked_reason = "logout"
    db_session.commit()
    assert _by_id(db_session) == {}


def test_native_oidc_other_browser_keeps_session(db_session: Session):
    _oidc_jti(db_session, revoked=True, reason="logout")
    _oidc_jti(db_session, issued_ago=timedelta(minutes=5))
    _row(db_session, sid="portal:alice@example.com:example-corp")
    s = _by_id(db_session)["portal:alice@example.com:example-corp"]
    assert s["verification"]["verdict"] == "valid"
    assert s["verification"]["credentials"] == 1


def test_stale_jti_from_before_the_row_is_ignored(db_session: Session):
    # A jti that died before this registry row started says nothing about it.
    _oidc_jti(db_session, issued_ago=timedelta(hours=10), ttl=timedelta(hours=1))
    _row(db_session, sid="portal:alice@example.com:example-corp")
    s = _by_id(db_session)["portal:alice@example.com:example-corp"]
    assert s["live_status"] == "online"
    assert s["verification"]["method"] == "traffic"


def test_unproven_oauth2_row_is_unverified_once_quiet(db_session: Session):
    _row(
        db_session,
        sid="portal:alice@example.com:example-corp",
        seen_ago=timedelta(minutes=20),
    )
    s = _by_id(db_session)["portal:alice@example.com:example-corp"]
    assert s["live_status"] == "unverified"
    assert s["live_status_label"] == "NON VÉRIFIÉ"


# ── app rows ────────────────────────────────────────────────────────────


def test_app_presence_dies_with_portal_credential(db_session: Session):
    jti = _oidc_jti(db_session)
    _row(db_session, sid="portal:alice@example.com:example-corp")
    _row(
        db_session,
        sid="app:alice@example.com:wiki",
        kind="app",
        protocol="HTTPS",
        target="wiki",
        details={"presence_only": True, "source": "subdomain_auth", "auth_source": "oidc"},
    )
    assert set(_by_id(db_session)) == {
        "portal:alice@example.com:example-corp",
        "app:alice@example.com:wiki",
    }
    jti.revoked = True
    jti.revoked_at = utcnow()
    jti.revoked_reason = "admin_disconnect"
    db_session.commit()
    assert _by_id(db_session) == {}


def test_presence_only_row_expires_after_idle_ttl(db_session: Session):
    _row(
        db_session,
        sid="app:alice@example.com:wiki",
        kind="app",
        protocol="HTTPS",
        target="wiki",
        seen_ago=liveness.PRESENCE_IDLE_TTL + timedelta(minutes=1),
        details={"presence_only": True, "source": "subdomain_auth"},
    )
    assert _by_id(db_session) == {}


def test_group_headline_prefers_online_member(db_session: Session):
    _oidc_jti(db_session)
    _row(
        db_session,
        sid="portal:alice@example.com:example-corp",
        seen_ago=timedelta(minutes=15),
    )
    _row(
        db_session,
        sid="app:alice@example.com:wiki",
        kind="app",
        protocol="HTTPS",
        target="wiki",
        details={"presence_only": True, "source": "subdomain_auth"},
    )
    view = sessions_service.sessions_view(
        db_session, viewer=None, kind=None, locale="fr"
    )
    group = view["groups"][0]
    assert group["live_status"] == "online"
    assert group["online_count"] == 1
    assert group["activity_at"]


# ── heartbeat & logout ──────────────────────────────────────────────────


def test_portal_heartbeat_slides_last_seen_and_throttles(db_session: Session):
    row = _row(
        db_session,
        sid="portal:alice@example.com:example-corp",
        seen_ago=timedelta(minutes=10),
    )
    before = liveness._aware(row.last_seen_at)
    assert touch_portal_heartbeat(
        db_session, identities=("alice@example.com", "alice"), breakglass=False
    ) == 1
    db_session.refresh(row)
    assert liveness._aware(row.last_seen_at) > before
    # Same identity inside the throttle window: no DB work at all.
    assert touch_portal_heartbeat(
        db_session, identities=("alice@example.com", "alice"), breakglass=False
    ) == 0
    # Break-glass heartbeat never touches an SSO row.
    assert touch_portal_heartbeat(
        db_session, identities=("alice@example.com",), breakglass=True
    ) == 0


def test_close_registry_after_logout_keeps_other_browser(db_session: Session):
    _oidc_jti(db_session)
    _row(db_session, sid="portal:alice@example.com:example-corp")
    assert close_registry_after_logout(db_session, identities=["alice"]) == 0
    assert db_session.query(ActiveSession).count() == 1


def test_logout_route_drops_unprovable_portal_row(client: TestClient, db_session: Session):
    client.get("/apps", headers=USER_HEADERS)
    assert db_session.query(ActiveSession).filter_by(kind="user").count() == 1
    resp = client.get("/logout", headers=USER_HEADERS, follow_redirects=False)
    assert resp.status_code in (302, 303, 307)
    db_session.expire_all()
    assert db_session.query(ActiveSession).filter_by(kind="user").count() == 0


# ── stream ──────────────────────────────────────────────────────────────


def _sse_events(body: str) -> list[tuple[str, dict]]:
    out = []
    for block in body.split("\n\n"):
        event, data = None, None
        for line in block.splitlines():
            if line.startswith("event: "):
                event = line[len("event: ") :]
            elif line.startswith("data: "):
                data = json.loads(line[len("data: ") :])
        if event:
            out.append((event, data or {}))
    return out


def test_stream_pushes_verified_snapshot(
    client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(sessions_service, "STREAM_MAX_SECONDS", 0.3)
    monkeypatch.setattr(sessions_service, "STREAM_TICK_SECONDS", 0.05)
    client.get("/apps", headers=ADMIN_HEADERS)
    resp = client.get("/api/sessions/stream", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert resp.headers.get("x-accel-buffering") == "no"
    events = _sse_events(resp.text)
    names = [e for e, _ in events]
    # Unchanged registry → exactly one snapshot, then the planned timeout.
    assert names.count("snapshot") == 1
    assert names[-1] == "timeout"
    snap = dict(events)["snapshot"]
    assert snap["server_time"]
    assert snap["total"] == 1
    session = snap["groups"][0]["sessions"][0]
    assert session["live_status"] == "online"
    assert "verification" in session


def test_stream_is_scoped_to_viewer(
    client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(sessions_service, "STREAM_MAX_SECONDS", 0.2)
    monkeypatch.setattr(sessions_service, "STREAM_TICK_SECONDS", 0.05)
    client.get("/apps", headers=ADMIN_HEADERS)
    client.get("/apps", headers=USER_HEADERS)
    resp = client.get("/api/sessions/stream", headers=USER_HEADERS)
    snap = dict(_sse_events(resp.text))["snapshot"]
    emails = {g["user_email"] for g in snap["groups"]}
    assert emails == {"alice@example.com"}


def test_unchanged_registry_gives_stable_fingerprint(db_session: Session):
    """Store-backed proofs re-run each tick must not churn the live feed."""
    chain = _bg_chain(db_session)
    _bg_portal_row(db_session, chain)
    _oidc_jti(db_session)
    _row(db_session, sid="portal:alice@example.com:example-corp")
    first = sessions_service.sessions_view(db_session, viewer=None, kind=None, locale="fr")
    second = sessions_service.sessions_view(db_session, viewer=None, kind=None, locale="fr")
    assert sessions_service._snapshot_fingerprint(first) == sessions_service._snapshot_fingerprint(second)
    methods = {s["verification"]["method"]: s["verification"] for s in first["sessions"]}
    assert methods["breakglass_jti"]["continuous"] is True
    assert methods["breakglass_jti"]["checked_at"] is None


def test_fingerprint_ignores_ticking_labels():
    base = {
        "groups": [
            {
                "user_email": "a@x",
                "duration": "1s",
                "sessions": [{"id": "1", "live_status": "online", "duration": "1s", "last_seen_ago": "il y a 1s"}],
            }
        ],
        "counts": {"all": 1},
    }
    later = json.loads(json.dumps(base))
    later["groups"][0]["duration"] = "9s"
    later["groups"][0]["sessions"][0]["duration"] = "9s"
    later["groups"][0]["sessions"][0]["last_seen_ago"] = "il y a 9s"
    assert sessions_service._snapshot_fingerprint(base) == sessions_service._snapshot_fingerprint(later)
    later["groups"][0]["sessions"][0]["live_status"] = "idle"
    assert sessions_service._snapshot_fingerprint(base) != sessions_service._snapshot_fingerprint(later)
