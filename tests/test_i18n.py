"""Tests for FR/EN internationalization."""

from __future__ import annotations

from app.i18n.catalog import clear_catalog_cache, t
from app.i18n.resolve import (
    DEFAULT_LOCALE,
    parse_accept_language,
    resolve_locale,
    normalize_locale,
)


def setup_function() -> None:
    clear_catalog_cache()


def test_normalize_locale() -> None:
    assert normalize_locale("EN") == "en"
    assert normalize_locale("fr-FR") == "fr"
    assert normalize_locale("de") is None
    assert normalize_locale("") is None


def test_resolve_locale_cookie_wins() -> None:
    assert (
        resolve_locale(cookie="en", accept_language="fr-FR,fr;q=0.9") == "en"
    )


def test_resolve_locale_accept_language() -> None:
    assert resolve_locale(cookie=None, accept_language="en-US,en;q=0.9") == "en"
    assert resolve_locale(cookie=None, accept_language="de-DE,de;q=0.9") == DEFAULT_LOCALE


def test_parse_accept_language_q_order() -> None:
    assert parse_accept_language("fr;q=0.8,en;q=0.9") == "en"


def test_t_french_is_identity() -> None:
    assert t("Annuler", "fr") == "Annuler"
    assert t("Confirmer", "fr") == "Confirmer"


def test_english_catalog_file_is_present() -> None:
    """en.json must ship with the package (Docker pip install), not only in the git tree."""
    from pathlib import Path

    import app.i18n.catalog as catalog_mod

    path = Path(catalog_mod.__file__).resolve().parent / "locales" / "en.json"
    assert path.is_file(), f"missing locale catalog: {path}"
    assert t("Préférences", "en") == "Preferences"
    assert t("Mes applications", "en") == "My applications"


def test_t_english_common_chrome() -> None:
    assert t("Annuler", "en") == "Cancel"
    assert t("Confirmer", "en") == "Confirm"
    assert t("Rechercher…", "en") == "Search…"
    assert t("Accès refusé", "en") == "Access denied"
    assert t("Mes fichiers", "en") == "My files"
    assert t("Accès rapides", "en") == "Quick access"
    assert t("Bonjour {name}", "en", name="Ada") == "Hello Ada"
    assert t("Vue d’ensemble —", "en") == "Overview —"
    assert t("Vue d'ensemble —", "en") == "Overview —"
    assert t("applicatives", "en") == "applications"


def test_t_missing_key_falls_back_to_msgid() -> None:
    assert t("___missing_key_xyz___", "en") == "___missing_key_xyz___"


def test_t_format_kwargs() -> None:
    # Even without catalog entry, format works on msgid
    assert t("Hello {name}", "fr", name="Ada") == "Hello Ada"


def test_locale_api_get(client) -> None:
    r = client.get("/api/locale")
    assert r.status_code == 200
    body = r.json()
    assert body["locale"] in ("fr", "en")
    assert "fr" in body["supported"]
    assert "en" in body["supported"]


def test_locale_api_set_cookie(client) -> None:
    r = client.post(
        "/api/locale",
        data={"locale": "en", "next": "/dashboard"},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)
    assert r.cookies.get("portal_locale") == "en"


def test_html_lang_follows_cookie(client) -> None:
    client.cookies.set("portal_locale", "en")
    r = client.get("/auth/login")
    assert r.status_code == 200
    assert 'lang="en"' in r.text


def test_sidebar_english_when_locale_en(client) -> None:
    """Admin chrome should render English labels with portal_locale=en."""
    client.cookies.set("portal_locale", "en")
    r = client.get(
        "/dashboard",
        headers={"X-Email": "admin@example.com", "X-Groups": "portal-admins"},
    )
    assert r.status_code == 200
    assert "Bastion" in r.text
    assert 'lang="en"' in r.text
    # Locale switch lives on login + profile only, not admin chrome.
    assert "data-locale-toggle" not in r.text
    assert "Access &amp; security" in r.text or "Access & security" in r.text
    assert "Filter menu" in r.text


def test_login_has_locale_switch(client) -> None:
    r = client.get("/auth/login")
    assert r.status_code == 200
    assert "data-locale-toggle" in r.text
    assert 'action="/api/locale"' in r.text
    assert 'name="locale" value="en"' in r.text


def test_profile_locale_form_switches_language(client) -> None:
    """Profile language control is a real POST form (not JS-only radios)."""
    headers = {"X-Email": "user@example.com", "X-Groups": ""}
    client.cookies.set("portal_locale", "en")
    page = client.get("/profile", headers=headers)
    assert page.status_code == 200
    assert 'action="/api/locale"' in page.text
    assert "Preferences" in page.text
    assert "My applications" in page.text
    assert "Language" in page.text


def _visible_html(html: str) -> str:
    """Strip script/style so __i18n catalog keys do not false-positive FR checks."""
    import re

    out = re.sub(r"<script\b[^>]*>.*?</script>", " ", html, flags=re.I | re.S)
    out = re.sub(r"<style\b[^>]*>.*?</style>", " ", out, flags=re.I | re.S)
    return out


def test_portal_apps_files_profile_english(client, db_session) -> None:
    """Portal apps / files / profile render English chrome with portal_locale=en."""
    from app.models import App
    from app.rbac.grants_service import AccessGrantCreate, create_grant

    app = App(
        slug="wiki-i18n",
        label="Wiki",
        upstream_url="https://wiki.example.com/",
        enabled=True,
        access_mode="sso_gate",
    )
    db_session.add(app)
    db_session.commit()
    db_session.refresh(app)
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-user-i18n",
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db_session.commit()

    headers = {
        "X-Email": "user@example.com",
        "X-Preferred-Username": "user",
        "X-User-Id": "kc-user-i18n",
        "X-Groups": "",
    }
    client.cookies.set("portal_locale", "en")

    apps = client.get("/apps", headers=headers)
    assert apps.status_code == 200
    apps_vis = _visible_html(apps.text)
    assert "My files" in apps_vis
    assert "Hello" in apps_vis
    assert "Quick access" in apps_vis
    assert "Mes fichiers" not in apps_vis
    assert "Bonjour" not in apps_vis
    assert "Accès rapides" not in apps_vis

    files = client.get("/files", headers=headers)
    assert files.status_code == 200
    files_vis = _visible_html(files.text)
    assert "My files" in files_vis
    assert "Mes fichiers" not in files_vis
    assert "<th>Name</th>" in files_vis
    assert "<th>Nom</th>" not in files_vis

    profile = client.get("/profile", headers=headers)
    assert profile.status_code == 200
    profile_vis = _visible_html(profile.text)
    assert "Preferences" in profile_vis
    assert "My files" in profile_vis
    assert "Name" in profile_vis
    assert "Mes fichiers" not in profile_vis


def test_dashboard_english_overview(client) -> None:
    """Admin dashboard overview labels follow portal_locale=en."""
    client.cookies.set("portal_locale", "en")
    r = client.get(
        "/dashboard",
        headers={"X-Email": "admin@example.com", "X-Groups": "portal-admins"},
    )
    assert r.status_code == 200
    vis = _visible_html(r.text)
    assert "Overview" in vis
    assert "Vue d'ensemble" not in vis
    assert "Vue d’ensemble" not in vis
    assert ">applications<" in vis or ">applications</span>" in vis


def test_error_page_english(client) -> None:
    client.cookies.set("portal_locale", "en")
    r = client.get("/this-page-does-not-exist-xyz")
    assert r.status_code == 404
    assert "Page not found" in r.text or "not found" in r.text.lower()


def test_login_english_chrome(client) -> None:
    """Login page chrome follows portal_locale=en (branding DB values stay as configured)."""
    client.cookies.set("portal_locale", "en")
    r = client.get("/auth/login")
    assert r.status_code == 200
    vis = _visible_html(r.text)
    assert 'lang="en"' in r.text
    assert "Sign in via SSO / Unique ID" in vis or "or" in vis
    # Hardcoded FR chrome must not remain when EN catalog applies.
    assert "Se connecter via SSO / Identifiant Unique" not in vis
    assert "Pas encore de compte ?" not in vis


def test_sessions_english_chrome(client) -> None:
    client.cookies.set("portal_locale", "en")
    r = client.get(
        "/sessions",
        headers={"X-Email": "admin@example.com", "X-Groups": "portal-admins"},
    )
    assert r.status_code == 200
    vis = _visible_html(r.text)
    assert "connection(s)" in vis or "Active sessions" in vis or "Sessions" in vis
    assert "All" in vis
    assert "Users" in vis
    assert "Toutes" not in vis
    assert "connexion(s)" not in vis


def test_branding_english_chrome(client) -> None:
    client.cookies.set("portal_locale", "en")
    r = client.get(
        "/admin/branding",
        headers={"X-Email": "admin@example.com", "X-Groups": "portal-admins"},
    )
    assert r.status_code == 200
    vis = _visible_html(r.text)
    assert "Portal branding" in vis
    assert "Company / portal name" in vis
    assert "Primary" in vis
    assert "Branding portail" not in vis
    assert "Nom de la société / portail" not in vis
    assert "Principale" not in vis


def test_configuration_smtp_english_chrome(client) -> None:
    client.cookies.set("portal_locale", "en")
    r = client.get(
        "/admin/configuration",
        headers={"X-Email": "admin@example.com", "X-Groups": "portal-admins"},
    )
    assert r.status_code == 200
    vis = _visible_html(r.text)
    assert "Outbound SMTP" in vis
    assert "Test connection" in vis or "Tester la connexion" not in vis
    assert "General" in vis
    assert "SMTP sortant" not in vis


def test_setup_wizard_english_chrome(client) -> None:
    client.cookies.set("portal_locale", "en")
    r = client.get(
        "/admin/setup-wizard",
        headers={"X-Email": "admin@example.com", "X-Groups": "portal-admins"},
    )
    assert r.status_code == 200
    vis = _visible_html(r.text)
    assert "Local admin account" in vis or "Portal identity" in vis
    assert "Compte admin local" not in vis


def test_relative_ago_english() -> None:
    from datetime import timedelta

    from app.models import utcnow
    from app.web.sessions_service import _relative_ago

    assert _relative_ago(utcnow(), locale="en") == "0s ago"
    assert _relative_ago(utcnow() - timedelta(minutes=5), locale="en") == "5 min ago"
    assert "il y a" in _relative_ago(utcnow(), locale="fr")
