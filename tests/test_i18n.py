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


def test_error_page_english(client) -> None:
    client.cookies.set("portal_locale", "en")
    r = client.get("/this-page-does-not-exist-xyz")
    assert r.status_code == 404
    assert "Page not found" in r.text or "not found" in r.text.lower()
