"""Coverage for Keycloak HTML error hint helpers."""

from __future__ import annotations

from app.oidc_bff_client import _keycloak_error_title_hint, _keycloak_http_error_hint


def test_keycloak_http_error_hint_cookie_and_expired():
    assert "cookie" in (_keycloak_http_error_hint("Cookie not found") or "").lower()
    assert "expiré" in (_keycloak_http_error_hint("session code expired") or "")
    assert "AUTH_SESSION" in (_keycloak_http_error_hint("We are sorry…") or "")


def test_keycloak_error_title_skips_login_and_reports_errors():
    login = "<html><title>Sign in to Default</title><body class='kc-form-login'></body></html>"
    assert _keycloak_error_title_hint(login, lower=login.lower()) is None
    err = "<html><title>Unexpected error</title></html>"
    hint = _keycloak_error_title_hint(err, lower=err.lower())
    assert hint is not None
    assert "Unexpected error" in hint
