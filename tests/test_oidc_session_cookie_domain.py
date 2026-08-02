"""bastion_session Domain=parent for subdomain auth_request."""

from __future__ import annotations

from fastapi.responses import Response

from app.oidc_bff import clear_oidc_session_cookie, set_oidc_session_cookie
from app.sso_settings import Settings


def _settings() -> Settings:
    return Settings(
        environment="test",
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        portal_domain="portal.ar-systems.fr",
        oidc_session_cookie_name="bastion_session",
        oidc_session_max_age=3600,
        oidc_session_jwt_secret="oidc-cookie-domain-hmac-key-32b!!",
    )


def test_bastion_session_cookie_uses_parent_domain():
    response = Response()
    set_oidc_session_cookie(response, "jwt-token-value", _settings())
    headers = response.headers.getlist("set-cookie")
    assert headers
    joined = " ".join(headers)
    assert "bastion_session=jwt-token-value" in joined
    assert "Domain=ar-systems.fr" in joined or "domain=ar-systems.fr" in joined


def test_clear_bastion_session_clears_parent_and_host_only():
    response = Response()
    clear_oidc_session_cookie(response, _settings())
    headers = response.headers.getlist("set-cookie")
    # Parent Domain clear + host-only clear
    assert len(headers) >= 2
    assert any("Domain=ar-systems.fr" in h or "domain=ar-systems.fr" in h for h in headers)
