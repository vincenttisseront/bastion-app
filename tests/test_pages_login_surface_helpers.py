"""Coverage for login-surface helpers extracted for Sonar S3776 / new coverage."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.models import App, RealmConfig
from app.web import pages


def test_auth_form_values_defaults():
    vals = pages._auth_form_values()
    assert vals["login_username_field"] == "username"
    assert vals["login_http_method"] == "POST"
    vals2 = pages._auth_form_values(
        auth_mode="generic_form",
        login_http_method="get",
        login_username_field="",
    )
    assert vals2["login_http_method"] == "GET"
    assert vals2["login_username_field"] == "username"


def test_apply_auth_config_sets_fields():
    app = App(
        slug="demo",
        label="Demo",
        upstream_url="https://app.example.com",
    )
    pages._apply_auth_config(
        app,
        auth_mode="generic_form",
        login_form_url=" https://app.example.com/login ",
        login_username_field=" user ",
        login_password_field=" pass ",
        login_http_method="post",
        login_extra_fields="k=v",
        sso_bridge="app_oidc",
        credential_mode="shared",
        identity_format="email",
        injected_cookie_scope="host_only",
    )
    assert app.auth_mode == "generic_form"
    assert app.login_form_url == "https://app.example.com/login"
    assert app.login_username_field == "user"
    assert app.sso_bridge == "trusted_headers"


def test_realm_is_login_ready():
    ready = RealmConfig(
        slug="default",
        name="Default",
        enabled=True,
        issuer_url="https://idp.example.com/realms/default",
        client_id="portal",
        show_on_login=True,
    )
    assert pages._realm_is_login_ready(ready) is True
    ready.enabled = False
    assert pages._realm_is_login_ready(ready) is False


def test_select_login_realm_by_want_and_fallback():
    a = RealmConfig(slug="alpha", name="A", enabled=True)
    b = RealmConfig(slug="beta", name="B", enabled=True)
    assert pages._select_login_realm([a, b], want="beta") is b
    assert pages._select_login_realm([a, b], want="") is a
    assert pages._select_login_realm([], want="x") is None


def test_native_realm_option_dicts():
    row = RealmConfig(
        slug="default",
        name="Default",
        enabled=True,
        oidc_mfa_enabled=False,
    )
    opts = pages._native_realm_option_dicts(
        MagicMock(),
        MagicMock(),
        [row],
        is_native=lambda *_a, **_k: True,
    )
    assert opts[0]["slug"] == "default"
    assert opts[0]["native"] is True
    assert opts[0]["mfa"] is False


def test_apply_m2m_config_ok():
    app = App(
        slug="demo",
        label="Demo",
        upstream_url="https://app.example.com",
    )
    err = pages._apply_m2m_config(
        app,
        access_mode="subdomain_proxy",
        m2m_accept_basic=True,
        m2m_accept_bearer=True,
        m2m_bypass_paths_raw="/api/health\n/metrics",
        m2m_bypass_long_timeout=True,
    )
    assert err == {}
    assert app.m2m_accept_basic is True
    assert "/api/health" in (app.m2m_bypass_paths or "")
