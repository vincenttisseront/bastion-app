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


def test_require_headless_login_inputs():
    from app.oidc_bff_client import (
        InvalidCredentialsError,
        OidcBffConfigError,
        _require_headless_login_inputs,
    )

    try:
        _require_headless_login_inputs(
            realm="", username="u", password="p", db=object()
        )
        raised = False
    except InvalidCredentialsError:
        raised = True
    assert raised is True

    try:
        _require_headless_login_inputs(
            realm="default", username="u", password="p", db=None
        )
        raised2 = False
    except OidcBffConfigError:
        raised2 = True
    assert raised2 is True

    realm, user = _require_headless_login_inputs(
        realm=" default ", username=" alice ", password="x", db=object()
    )
    assert realm == "default"
    assert user == "alice"
