"""Admin FQDN cookie-domain warning — shared parent + CSS hidden fix."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import App
from app.robotic.robotic_session_cookies import shared_parent_domain
from app.sso_settings import Settings, get_settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
}


def _grommunio_app(db: Session) -> App:
    app = App(
        slug="grommunio",
        label="Grommunio",
        upstream_url="https://vmapps-mail01.ar-systems.fr:8443/",
        access_mode="subdomain_proxy",
        public_fqdn="webmail.ar-systems.fr",
        robotic_driver="generic_form",
        auth_mode="generic_form",
        login_form_url="https://vmapps-mail01.ar-systems.fr:8443/api/v1/login",
        credential_mode="identite_utilisateur",
        enabled=True,
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def test_webmail_shares_parent_with_portal():
    assert (
        shared_parent_domain("webmail.ar-systems.fr", "portal.ar-systems.fr")
        == "ar-systems.fr"
    )


def test_edit_grommunio_warning_starts_hidden_and_css_respects_hidden(
    client: TestClient, db_session: Session
):
    """
    Regression: .alert { display:flex } used to override the HTML hidden
    attribute, so the orange banner always showed for subdomain apps even when
    webmail.ar-systems.fr and portal.ar-systems.fr share ar-systems.fr.
    """
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        portal_domain="portal.ar-systems.fr",
    )
    _grommunio_app(db_session)
    page = client.get("/admin/apps/grommunio/edit", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    html = page.text
    assert 'id="public_fqdn"' in html
    assert 'value="webmail.ar-systems.fr"' in html
    assert 'data-portal-domain="portal.ar-systems.fr"' in html
    assert 'id="fqdn-cookie-domain-warning"' in html
    # Markup must keep the warning hidden until JS decides otherwise
    assert 'id="fqdn-cookie-domain-warning"' in html
    assert "hidden" in html.split('id="fqdn-cookie-domain-warning"')[1].split(">")[0]
    assert "alert alert-warn" in html.split('id="fqdn-cookie-domain-warning"')[1].split(">")[0]
    css = client.get("/static/css/bastion-components.css")
    assert css.status_code == 200
    assert ".alert[hidden]{display:none!important}" in css.text.replace(" ", "")

    js = client.get("/static/js/bastion.js")
    assert js.status_code == 200
    assert "function sharedParentDomain" in js.text
    assert "normalizeHostname" in js.text
