"""ActiveSession registry TTL purge (idle + absolute)."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from app.models import ActiveSession, utcnow
from app.web.sessions_service import (
    BREAKGLASS_ABSOLUTE_TTL,
    BREAKGLASS_IDLE_TTL,
    SESSION_ABSOLUTE_TTL,
    expire_stale_sessions,
    get_active_sessions,
)


def _row(
    db: Session,
    *,
    sid: str,
    protocol: str,
    started_ago: timedelta,
    last_seen_ago: timedelta,
) -> ActiveSession:
    now = utcnow()
    row = ActiveSession(
        id=sid,
        kind="user",
        user_email=f"{sid}@example.com",
        username=sid,
        realm="ar-systems",
        protocol=protocol,
        target="portal",
        status="active",
        started_at=now - started_ago,
        last_seen_at=now - last_seen_ago,
    )
    db.add(row)
    db.commit()
    return row


def test_expire_breakglass_absolute(db_session: Session):
    _row(
        db_session,
        sid="bg-abs",
        protocol="BREAKGLASS",
        started_ago=BREAKGLASS_ABSOLUTE_TTL + timedelta(minutes=5),
        last_seen_ago=timedelta(minutes=1),  # still "active" recently
    )
    assert expire_stale_sessions(db_session) == 1
    assert db_session.query(ActiveSession).count() == 0


def test_expire_breakglass_idle(db_session: Session):
    _row(
        db_session,
        sid="bg-idle",
        protocol="BREAKGLASS",
        started_ago=timedelta(hours=1),
        last_seen_ago=BREAKGLASS_IDLE_TTL + timedelta(minutes=1),
    )
    assert expire_stale_sessions(db_session) == 1


def test_expire_oidc_absolute(db_session: Session):
    _row(
        db_session,
        sid="oidc-abs",
        protocol="OIDC",
        started_ago=SESSION_ABSOLUTE_TTL + timedelta(hours=1),
        last_seen_ago=timedelta(minutes=1),
    )
    assert expire_stale_sessions(db_session) == 1


def test_keep_fresh_oidc(db_session: Session):
    _row(
        db_session,
        sid="oidc-ok",
        protocol="OIDC",
        started_ago=timedelta(hours=2),
        last_seen_ago=timedelta(minutes=5),
    )
    assert expire_stale_sessions(db_session) == 0
    sessions = get_active_sessions(db_session)
    assert len(sessions) == 1
