"""SQLAlchemy engine and session factory (config DB + optional hot routing)."""

import logging
from collections.abc import Generator

from fastapi import Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.hot_store import make_session_factory, refresh_hot_engine_if_stale
from app.db_cipher import create_portal_engine
from app.sso_settings import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()
engine = create_portal_engine(settings.database_url, settings)
SessionLocal = make_session_factory(engine)


def get_db(request: Request) -> Generator[Session, None, None]:
    db = SessionLocal()
    request.state.db = db
    try:
        refresh_hot_engine_if_stale(db, settings)
    except SQLAlchemyError:
        logger.warning("hot store: config refresh failed", exc_info=True)
        db.rollback()
    try:
        yield db
    finally:
        db.close()


def release_db_connection(db: Session) -> None:
    """
    Return checked-out pool connections before a long ``await``.

    FastAPI keeps the request-scoped Session for the whole request. The config
    DB uses NullPool, but the Postgres hot-store engine is pooled: without this,
    concurrent ``auth_request`` handlers (subdomain-auth → oauth2-proxy) can hold
    every hot-store slot. After ``close()``, the next ORM use on the same Session
    checks out a fresh connection.
    """
    db.close()
