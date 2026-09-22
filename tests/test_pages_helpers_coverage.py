"""Coverage for admin pages helpers on the Sonar new-code leak period."""

from __future__ import annotations

from app.models import App
from app.sso_settings import Settings, get_settings
from app.web import pages


def _settings() -> Settings:
    get_settings.cache_clear()
    return Settings(
        portal_domain="portal.example.com",
        sso_portal_default_realm_slug="default",
        vault_portal_internal_token="test-secret-for-encrypt-32b!",
    )  # type: ignore[call-arg]


def _app(**extra) -> App:
    return App(
        slug=extra.pop("slug", "demo"),
        label=extra.pop("label", "Demo"),
        upstream_url=extra.pop("upstream_url", "https://app.example.com"),
        **extra,
    )


def test_normalize_description_truncates_and_empty():
    assert pages._normalize_description(None) is None
    assert pages._normalize_description("  ") is None
    long = "x" * (pages._DESC_MAX + 50)
    out = pages._normalize_description(long)
    assert out is not None
    assert len(out) == pages._DESC_MAX


def test_m2m_bypass_paths_text_raw_and_none_app():
    assert pages._m2m_bypass_paths_text(app=None) == ""
    text = pages._m2m_bypass_paths_text(raw="/api/\n/health")
    assert "/api/" in text
    assert "/health" in text


def test_apply_m2m_config_returns_path_errors():
    app = _app()
    err = pages._apply_m2m_config(
        app,
        access_mode="subdomain_proxy",
        m2m_accept_basic=True,
        m2m_accept_bearer=False,
        m2m_bypass_paths_raw="/\nhttps://evil.example.com/x",
        m2m_bypass_long_timeout=False,
    )
    assert "m2m_bypass_paths" in err


def test_apply_crushftp_admin_config_encrypts_and_clears():
    settings = _settings()
    app = _app(slug="crush", label="Crush")
    err = pages._apply_crushftp_admin_config(
        app,
        settings,
        crushftp_admin_base_url=" https://ftp.example.com/ ",
        crushftp_admin_server_group=" Main ",
        crushftp_admin_username=" admin ",
        crushftp_admin_password="s3cret",
        crushftp_vfs_base_path="\\data\\share\\",
    )
    assert err == {}
    assert app.crushftp_admin_base_url == "https://ftp.example.com/"
    assert app.crushftp_admin_server_group == "Main"
    assert app.crushftp_admin_username == "admin"
    assert app.crushftp_vfs_base_path == "/data/share"
    assert app.crushftp_admin_password_encrypted


def test_apply_crushftp_admin_config_encrypt_failure(monkeypatch):
    settings = _settings()
    app = _app(slug="crush", label="Crush")

    def boom(*_a, **_k):
        raise ValueError("no key")

    monkeypatch.setattr(pages, "encrypt_secret", boom)
    err = pages._apply_crushftp_admin_config(
        app,
        settings,
        crushftp_admin_base_url="",
        crushftp_admin_server_group="",
        crushftp_admin_username="",
        crushftp_admin_password="plain",
    )
    assert "crushftp_admin_password" in err


def test_warn_subdomain_fqdn_parent_noop_and_empty():
    pages._warn_if_fqdn_cookie_domain_incompatible(
        access_mode="portal_path",
        public_fqdn="app.example.com",
        portal_domain="portal.example.com",
        app_slug="demo",
    )
    pages._warn_if_fqdn_cookie_domain_incompatible(
        access_mode="subdomain_proxy",
        public_fqdn="",
        portal_domain="portal.example.com",
        app_slug="demo",
    )


def test_validate_auth_fields_rejects_vault_on_sso_gate():
    err = pages._validate_auth_fields(
        access_mode="sso_gate",
        auth_mode="generic_form",
        login_form_url="https://app.example.com/login",
        login_username_field="u",
        login_password_field="p",
        login_http_method="POST",
        login_extra_fields="",
    )
    assert "auth_mode" in err


def test_validate_auth_fields_app_oidc_requires_login_url():
    err = pages._validate_auth_fields(
        access_mode="subdomain_proxy",
        auth_mode="sso",
        login_form_url="",
        login_username_field="u",
        login_password_field="p",
        login_http_method="POST",
        login_extra_fields="",
        sso_bridge="app_oidc",
    )
    assert "login_form_url" in err


def test_hot_store_flash_sets_cookie(monkeypatch):
    seen = {}

    def fake_flash(response, message, level, token):
        seen["message"] = message
        seen["level"] = level
        seen["token"] = token

    monkeypatch.setattr(pages, "flash_redirect", fake_flash)
    resp = object()
    settings = _settings()
    out = pages._hot_store_flash(resp, "ok", "success", settings)
    assert out is resp
    assert seen["message"] == "ok"
    assert seen["level"] == "success"


def test_ordered_enabled_realms_puts_default_first(db_session):
    from app.models import RealmConfig
    from app.secret_crypto import encrypt_secret

    settings = _settings()
    a = RealmConfig(
        slug="alpha",
        name="Alpha",
        enabled=True,
        issuer_url="https://idp.example.com/realms/alpha",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("s", settings),
        redirect_uri="https://portal.example.com/oauth2/alpha/callback",
        oauth2_proxy_port=4181,
        is_default=False,
    )
    b = RealmConfig(
        slug="default",
        name="Default",
        enabled=True,
        issuer_url="https://idp.example.com/realms/default",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("s", settings),
        redirect_uri="https://portal.example.com/oauth2/default/callback",
        oauth2_proxy_port=4180,
        is_default=True,
    )
    db_session.add_all([a, b])
    db_session.commit()
    ordered = pages._ordered_enabled_realms(db_session, b)
    assert ordered[0].slug == "default"
    assert {r.slug for r in ordered} == {"default", "alpha"}
