"""Shared pytest fixtures."""

import pytest
import respx
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import get_db
from app.main import app
from app.models import Base
from app.sso_settings import Settings, get_settings


@pytest.fixture()
def db_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db_session(db_engine):
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db_engine):
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    def override_get_settings():
        return Settings(
            vault_portal_internal_token="test-secret",
            portal_secret_encryption_key="test-encryption-key-for-pytest-only",
            database_url="sqlite://",
        )

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_get_settings
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def mock_http():
    """Generic respx mock for connection-test modules."""
    with respx.mock(assert_all_called=False) as mock:
        yield mock


@pytest.fixture
def oidc_discovery_ok(mock_http):
    def _register(issuer_base: str):
        mock_http.get(f"{issuer_base}/.well-known/openid-configuration").mock(
            return_value=Response(
                200,
                json={
                    "issuer": issuer_base,
                    "jwks_uri": f"{issuer_base}/protocol/openid-connect/certs",
                    "token_endpoint": f"{issuer_base}/protocol/openid-connect/token",
                    "authorization_endpoint": f"{issuer_base}/protocol/openid-connect/auth",
                },
            )
        )

    return _register


@pytest.fixture
def http_probe_ok(mock_http):
    def _register(url: str, status_code: int = 200):
        mock_http.get(url).mock(return_value=Response(status_code))

    return _register
