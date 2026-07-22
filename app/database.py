"""SQLAlchemy engine and session factory."""

from collections.abc import Generator

from fastapi import Request
from sqlalchemy.orm import Session, sessionmaker

from app.db_cipher import create_portal_engine
from app.sso_settings import get_settings

settings = get_settings()
engine = create_portal_engine(settings.database_url, settings)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db(request: Request) -> Generator[Session, None, None]:
    db = SessionLocal()
    request.state.db = db
    try:
        yield db
    finally:
        db.close()
