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
from app.vault.encryption_key_store import reset_active_cache_for_tests
from app.breakglass import reset_breakglass_ephemeral_secret_for_tests

# Injected by TrustedHeadersTestClient so forged X-Email/X-Groups in tests still
# satisfy SDD-001 (identity headers require X-Portal-Internal-Token).
TEST_PORTAL_INTERNAL_TOKEN = "test-secret"


class TrustedHeadersTestClient(TestClient):
    """TestClient that auto-adds the nginx internal token on every request."""

    def request(self, method, url, **kwargs):  # type: ignore[override]
        headers = kwargs.get("headers")
        merged: dict[str, str] = {}
        if headers:
            merged.update({str(k): str(v) for k, v in dict(headers).items()})
        # Opt-out for negative tests (spoof without token).
        omit = False
        for key in list(merged):
            if key.lower() == "x-test-omit-internal-token":
                omit = True
                merged.pop(key)
        lower = {k.lower(): k for k in merged}
        if not omit and "x-portal-internal-token" not in lower:
            merged["X-Portal-Internal-Token"] = TEST_PORTAL_INTERNAL_TOKEN
        kwargs["headers"] = merged
        return super().request(method, url, **kwargs)


@pytest.fixture(autouse=True)
def _isolate_fernet_key_store(tmp_path, monkeypatch):
    """Isolate VAULT_KEYS_DIR per test and clear in-memory key cache."""
    import os

    reset_active_cache_for_tests()
    reset_breakglass_ephemeral_secret_for_tests()
    keys = tmp_path / "vault-keys"
    keys.mkdir()
    monkeypatch.setenv("VAULT_KEYS_DIR", str(keys))
    monkeypatch.setenv("PORTAL_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PORTAL_ENVIRONMENT", "test")
    monkeypatch.setenv("IP_GEOLOC_ENABLED", "false")
    monkeypatch.setenv("SESSION_HOP_SECRET", "test-session-hop-secret-for-pytest")
    # Prefer a known test key so lifespan migrate path is deterministic when client starts.
    if not os.environ.get("PORTAL_SECRET_ENCRYPTION_KEY"):
        monkeypatch.setenv(
            "PORTAL_SECRET_ENCRYPTION_KEY", "test-encryption-key-for-pytest-only"
        )
    get_settings.cache_clear()
    from app.request_client_ip import clear_trusted_proxy_cache

    clear_trusted_proxy_cache()
    yield
    reset_active_cache_for_tests()
    reset_breakglass_ephemeral_secret_for_tests()
    get_settings.cache_clear()
    clear_trusted_proxy_cache()


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
def client(db_engine, monkeypatch):
    from fastapi import Request

    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
    # Middleware opens its own session (request.state.db is already closed).
    monkeypatch.setattr(
        "app.breakglass_cookie_middleware.SessionLocal",
        session_factory,
    )
    monkeypatch.setattr(
        "app.security.banning.middleware.SessionLocal",
        session_factory,
    )

    def override_get_db(request: Request):
        db = session_factory()
        request.state.db = db
        try:
            yield db
        finally:
            db.close()

    def override_get_settings():
        return Settings(
            environment="test",
            vault_portal_internal_token=TEST_PORTAL_INTERNAL_TOKEN,
            breakglass_jwt_secret="test-bg-jwt-secret",
            breakglass_jwt_secret_fallback_enabled=True,
            session_hop_secret="test-session-hop-secret-for-pytest",
            portal_secret_encryption_key="test-encryption-key-for-pytest-only",
            database_url="sqlite://",
        )

    # Middleware calls get_settings() directly (not Depends).
    monkeypatch.setattr(
        "app.breakglass_cookie_middleware.get_settings",
        override_get_settings,
    )

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_get_settings
    with TrustedHeadersTestClient(app) as test_client:
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
