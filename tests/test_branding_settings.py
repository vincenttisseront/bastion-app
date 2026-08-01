"""BrandingSettings singleton — CRUD, uploads, neutral defaults."""

from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy.orm import Session

from app import branding as branding_mod
from app.models import AuditLog, BrandingSettings
from app.web.app_logos import LogoValidationError


ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
}


@pytest.fixture()
def branding_dirs(tmp_path, monkeypatch):
    data = tmp_path / "sso-portal"
    (data / "uploads" / "branding").mkdir(parents=True)
    monkeypatch.setattr(branding_mod, "get_portal_data_dir", lambda settings=None: data)
    return data


def _png_bytes(size: tuple[int, int] = (64, 64)) -> bytes:
    img = Image.new("RGBA", size, (16, 185, 129, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_branding_defaults_seeded_on_read(db_session: Session):
    data = branding_mod.get_branding_settings(db_session)
    assert data["company_name"] == "Portail sécurisé"
    assert data["page_title"] == "Connexion"
    assert data["accent_color"] == "#10b981"
    assert data["secondary_color"] == "#059669"
    assert data["highlight_color"] == "#34d399"
    assert "--accent:#10b981" in data["css_vars"]
    assert "--accent-dim:#059669" in data["css_vars"]
    assert "--accent-h:#34d399" in data["css_vars"]
    assert data["default_theme"] == "dark"
    assert data["show_product_branding"] is False
    assert data["favicon_url"] == "/static/img/generic-shield.svg"
    row = db_session.query(BrandingSettings).filter_by(id=1).one()
    assert row.company_name == "Portail sécurisé"
    assert row.secondary_color == "#059669"
    assert row.highlight_color == "#34d399"


def test_admin_branding_page_requires_admin(client: TestClient):
    r = client.get("/admin/branding", follow_redirects=False)
    assert r.status_code in (401, 302, 403)


def test_admin_branding_save(client: TestClient, db_session: Session, branding_dirs):
    r = client.post(
        "/admin/branding",
        headers=ADMIN_HEADERS,
        data={
            "company_name": "ACME Corp",
            "page_title": "Connexion ACME",
            "accent_color": "#2563eb",
            "secondary_color": "#1d4ed8",
            "highlight_color": "#60a5fa",
            "default_theme": "light",
            "welcome_text": "Bienvenue",
            "footer_text": "© ACME",
            "support_contact": "help@acme.test",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    data = branding_mod.get_branding_settings(db_session)
    assert data["company_name"] == "ACME Corp"
    assert data["page_title"] == "Connexion ACME"
    assert data["accent_color"] == "#2563eb"
    assert data["secondary_color"] == "#1d4ed8"
    assert data["highlight_color"] == "#60a5fa"
    assert "--accent:#2563eb" in data["css_vars"]
    assert "--accent-dim:#1d4ed8" in data["css_vars"]
    assert "--accent-h:#60a5fa" in data["css_vars"]
    assert data["default_theme"] == "light"
    assert data["welcome_text"] == "Bienvenue"
    assert data["footer_text"] == "© ACME"
    assert data["support_contact"] == "help@acme.test"
    assert data["show_product_branding"] is False

    audit = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "branding_settings.updated")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.actor == "admin@example.com"


def test_admin_branding_invalid_color(client: TestClient, branding_dirs):
    r = client.post(
        "/admin/branding",
        headers=ADMIN_HEADERS,
        data={
            "company_name": "X",
            "page_title": "Y",
            "accent_color": "red",
            "secondary_color": "#059669",
            "highlight_color": "#34d399",
            "default_theme": "dark",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302


def test_branding_css_vars_rgba(db_session: Session):
    data = branding_mod.branding_css_vars("#2563eb", "#1d4ed8", "#60a5fa", theme="dark")
    assert "--accent:#2563eb" in data
    assert "--accent-dim:#1d4ed8" in data
    assert "--accent-h:#60a5fa" in data
    assert "rgba(37,99,235," in data


def test_logo_upload_and_media(
    client: TestClient, db_session: Session, branding_dirs
):
    up = client.post(
        "/admin/branding/logo",
        headers=ADMIN_HEADERS,
        files={"file": ("logo.png", _png_bytes(), "image/png")},
        follow_redirects=False,
    )
    assert up.status_code == 302
    data = branding_mod.get_branding_settings(db_session)
    assert data["logo_url"]
    assert data["logo_url"].startswith("/media/branding/")
    media = client.get(data["logo_url"])
    assert media.status_code == 200
    assert media.headers["content-type"].startswith("image/")


def test_favicon_upload_rejects_svg(client: TestClient, branding_dirs):
    r = client.post(
        "/admin/branding/favicon",
        headers=ADMIN_HEADERS,
        files={"file": ("x.svg", b"<svg xmlns='http://www.w3.org/2000/svg'></svg>", "image/svg+xml")},
        follow_redirects=False,
    )
    assert r.status_code == 302


def test_favicon_too_large(branding_dirs):
    with pytest.raises(LogoValidationError):
        branding_mod.process_favicon_bytes(b"\x00" * (256 * 1024 + 1))


def test_favicon_png_ok(client: TestClient, db_session: Session, branding_dirs):
    r = client.post(
        "/admin/branding/favicon",
        headers=ADMIN_HEADERS,
        files={"file": ("fav.png", _png_bytes((32, 32)), "image/png")},
        follow_redirects=False,
    )
    assert r.status_code == 302
    data = branding_mod.get_branding_settings(db_session)
    assert data["favicon_path"]
    assert data["favicon_url"].startswith("/media/branding/")


def test_clear_logo(client: TestClient, db_session: Session, branding_dirs):
    client.post(
        "/admin/branding/logo",
        headers=ADMIN_HEADERS,
        files={"file": ("logo.png", _png_bytes(), "image/png")},
    )
    r = client.post(
        "/admin/branding/logo/delete",
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )
    assert r.status_code == 302
    data = branding_mod.get_branding_settings(db_session)
    assert data["logo_path"] is None
