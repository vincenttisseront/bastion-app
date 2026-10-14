"""UTCDateTime: aware UTC values whatever the backend stores."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import AuditLog, utcnow


def test_sqlite_round_trip_returns_aware_utc(db_session: Session):
    db_session.add(AuditLog(actor="a", action="tz.check"))
    db_session.commit()
    db_session.expire_all()

    row = db_session.query(AuditLog).filter_by(action="tz.check").one()

    assert row.created_at.tzinfo is not None
    assert row.created_at.utcoffset() == timedelta(0)
    assert utcnow() - row.created_at < timedelta(minutes=1)


def test_non_utc_input_is_stored_as_utc(db_session: Session):
    paris = timezone(timedelta(hours=2))
    db_session.add(
        AuditLog(actor="a", action="tz.paris", created_at=datetime(2026, 1, 1, 12, 0, tzinfo=paris))
    )
    db_session.commit()
    db_session.expire_all()

    row = db_session.query(AuditLog).filter_by(action="tz.paris").one()

    assert row.created_at == datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)


def test_naive_input_is_taken_as_utc(db_session: Session):
    db_session.add(AuditLog(actor="a", action="tz.naive", created_at=datetime(2026, 1, 1, 12, 0)))
    db_session.commit()
    db_session.expire_all()

    row = db_session.query(AuditLog).filter_by(action="tz.naive").one()

    assert row.created_at == datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
