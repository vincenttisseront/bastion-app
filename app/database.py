"""SQLAlchemy engine and session factory (config DB + optional hot routing)."""

from collections.abc import Generator

from fastapi import Request
from sqlalchemy.orm import Session

from app.db.hot_store import make_session_factory, sync_hot_engine_from_config
from app.db_cipher import create_portal_engine
from app.sso_settings import get_settings

settings = get_settings()
engine = create_portal_engine(settings.database_url, settings)
SessionLocal = make_session_factory(engine)


def get_db(request: Request) -> Generator[Session, None, None]:
    db = SessionLocal()
    request.state.db = db
    # Refresh hot-engine cache from portal_settings (cheap when TTL warm).
    try:
        sync_hot_engine_from_config(db, settings)
    except Exception:
        pass
    try:
        yield db
    finally:
        db.close()


def release_db_connection(db: Session) -> None:
    """
    Return the checked-out pool connection before a long ``await``.

    FastAPI keeps the request-scoped Session for the whole request; without this,
    concurrent ``auth_request`` handlers (subdomain-auth → oauth2-proxy) hold all
    QueuePool slots and starve the rest of the app. After ``close()``, the next
    ORM use on the same Session checkouts a fresh connection.
    """
    db.close()
