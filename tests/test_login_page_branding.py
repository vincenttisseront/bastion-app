"""Public login page uses BrandingSettings — no Bastion Pro by default."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.branding import update_branding_settings
from app.breakglass_store import set_breakglass_password
from app.models import RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings


def _seed_login_prereqs(db: Session) -> None:
    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    realm = RealmConfig(
        slug="ar-systems",
        name="AR-SYSTEMS",
        issuer_url="https://keycloak.example/realms/ar-systems",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", settings),
        redirect_uri="https://portal.example/oauth2/ar-systems/callback",
        oauth2_proxy_port=4180,
        is_default=True,
        enabled=True,
        last_test_status="ok",
    )
    db.add(realm)
    db.commit()
    set_breakglass_password(db, "admin", "super-secret-password")


def test_login_page_neutral_defaults(client: TestClient, db_session: Session):
    _seed_login_prereqs(db_session)
    r = client.get("/auth/login")
    assert r.status_code == 200
    assert "Portail sécurisé" in r.text
    assert "Bastion Pro" not in r.text
    assert "bastion.css" not in r.text
    assert "/static/portal.css" in r.text
    assert "/static/portal-theme.js" in r.text
    assert "bastion-theme.js" not in r.text
    assert "generic-shield.svg" in r.text or "/media/branding/" in r.text
    assert 'name="generator"' not in r.text.lower()
    assert "--accent: #10b981" in r.text or "--accent:#10b981" in r.text


def test_login_page_custom_branding(client: TestClient, db_session: Session):
    _seed_login_prereqs(db_session)
    update_branding_settings(
        db_session,
        actor="test",
        company_name="Société Demo",
        page_title="Accès Demo",
        accent_color="#ef4444",
        welcome_text="Bienvenue collaborateurs",
        footer_text="Confidential",
        support_contact="soc@demo.test",
        show_product_branding=False,
    )
    r = client.get("/auth/login")
    assert r.status_code == 200
    assert "Société Demo" in r.text
    assert "Accès Demo" in r.text
    assert "Bienvenue collaborateurs" in r.text
    assert "Confidential" in r.text
    assert "soc@demo.test" in r.text
    assert "#ef4444" in r.text
    assert "Bastion Pro" not in r.text


def test_login_page_product_branding_opt_in(client: TestClient, db_session: Session):
    _seed_login_prereqs(db_session)
    update_branding_settings(
        db_session,
        actor="test",
        show_product_branding=True,
    )
    r = client.get("/auth/login")
    assert r.status_code == 200
    assert "Bastion" in r.text
    assert "Pro" in r.text


def test_portal_static_aliases(client: TestClient):
    css = client.get("/static/portal.css")
    assert css.status_code == 200
    assert "text/css" in css.headers.get("content-type", "")
    # Absolute imports: /static/portal.css alias must not break @import resolution
    assert b"/static/css/bastion-tokens.css" in css.content
    assert b"@import url('./" not in css.content
    js = client.get("/static/portal-theme.js")
    assert js.status_code == 200
    assert client.get("/static/css/bastion-tokens.css").status_code == 200
