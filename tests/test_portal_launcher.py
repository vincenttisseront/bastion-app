"""Portal launcher (UI lot 3): monograms, favourites first, contextual 404, login notice."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import App
from app.rbac.grants_service import AccessGrantCreate, create_grant
from app.web.portal_enrichment import MONOGRAM_TONES, monogram, monogram_tone

USER_HEADERS = {
    "X-Email": "alice@example.com",
    "X-Preferred-Username": "alice",
    "X-User-Id": "kc-user-alice",
    "X-Groups": "team-ops",
}


def _launchable_app(db: Session, *, slug: str, label: str, description: str = "") -> App:
    app = App(
        slug=slug,
        label=label,
        description=description,
        upstream_url=f"https://{slug}.example.com/",
        enabled=True,
        access_mode="sso_gate",
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    create_grant(
        db,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-user-alice",
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db.commit()
    return app


def test_monogram_skips_articles_and_keeps_acronyms():
    assert monogram("Transfert de fichiers") == "TF"
    assert monogram("Wiki") == "Wi"
    assert monogram("CRM") == "CR"
    assert monogram("l'intranet") == "In"
    assert monogram("") == "?"


def test_monogram_tone_is_stable_and_bounded():
    assert monogram_tone("wiki") == monogram_tone("wiki")
    assert all(0 <= monogram_tone(s) < MONOGRAM_TONES for s in ("a", "wiki", "gitlab", ""))


def test_apps_page_shows_monogram_description_and_search(client: TestClient, db_session: Session):
    _launchable_app(db_session, slug="wiki", label="Wiki interne", description="Documentation des équipes")

    page = client.get("/apps", headers=USER_HEADERS)
    assert page.status_code == 200
    html = page.text
    assert "app-monogram" in html
    assert ">WI<" in html
    assert "Documentation des équipes" in html
    assert 'aria-keyshortcuts="Control+K Meta+K /"' in html
    # One title, the search, the apps: no eyebrow, no « ouvrables » jargon, no side nav.
    assert "portal-eyebrow" not in html
    assert "ouvrable" not in html
    assert "portal-apps-nav" not in html


def test_apps_page_hides_empty_favourites_and_lists_them_first(client: TestClient, db_session: Session):
    wiki = _launchable_app(db_session, slug="wiki", label="Wiki")
    _launchable_app(db_session, slug="crm", label="CRM")

    page = client.get("/apps", headers=USER_HEADERS)
    assert 'data-apps-section="favorites"' not in page.text

    assert client.post(f"/api/apps/{wiki.id}/favorite", headers=USER_HEADERS).status_code == 200
    page = client.get("/apps", headers=USER_HEADERS)
    html = page.text
    assert html.index('data-apps-section="favorites"') < html.index('data-apps-section="applications"')
    assert "data-apps-favorites" in html


def test_404_offers_sign_in_without_session(client: TestClient):
    r = client.get("/no-such-page-lot3")
    assert r.status_code == 404
    assert 'href="/auth/login"' in r.text
    assert "error-code--neutral" in r.text


def test_404_offers_way_back_to_apps_with_session(client: TestClient):
    # /errors/404 renders the same template through the test settings override
    # (the catch-all handler reads the process settings, which the client does
    # not authenticate against).
    r = client.get("/errors/404", headers=USER_HEADERS)
    assert r.status_code == 404
    assert 'href="/apps"' in r.text
    assert 'href="/auth/login"' not in r.text


def test_login_no_method_notice_appears_at_most_once(client: TestClient):
    r = client.get("/auth/login")
    assert r.status_code == 200
    assert r.text.count("Aucun mode de connexion n&#39;est disponible") + r.text.count(
        "Aucun mode de connexion n'est disponible"
    ) <= 1
