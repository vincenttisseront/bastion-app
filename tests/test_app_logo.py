"""App logo upload / delete — content validation and portal fallback."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy.orm import Session

from app.models import App, AuditLog
from app.web import app_logos


ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
}

USER_HEADERS = {
    "X-Email": "alice@example.com",
    "X-Preferred-Username": "alice",
    "X-User-Id": "kc-user-alice",
    "X-Groups": "team-ops",
}


@pytest.fixture()
def logo_dirs(tmp_path, monkeypatch):
    """Point logo storage at a tmp volume (not site-packages/static)."""
    data = tmp_path / "sso-portal"
    logos = data / "uploads" / "app-logos"
    logos.mkdir(parents=True)
    monkeypatch.setattr(app_logos, "get_portal_data_dir", lambda settings=None: data)
    return data, logos


def _png_bytes(size: tuple[int, int] = (64, 64), color=(16, 185, 129)) -> bytes:
    img = Image.new("RGB", size, color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _app(db: Session, *, slug: str = "wiki", label: str = "Wiki", **kwargs) -> App:
    app = App(
        slug=slug,
        label=label,
        upstream_url=kwargs.pop("upstream_url", f"https://{slug}.example.com/"),
        enabled=True,
        access_mode="sso_gate",
        description=kwargs.pop("description", None),
        logo_path=kwargs.pop("logo_path", None),
        **kwargs,
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def test_app_logo_upload_valid(client: TestClient, db_session: Session, logo_dirs):
    _data, logos = logo_dirs
    app = _app(db_session)

    resp = client.post(
        f"/admin/apps/{app.id}/logo",
        headers=ADMIN_HEADERS,
        files={"file": ("logo.png", _png_bytes(), "image/png")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["logo_url"].startswith("/media/app-logos/")
    assert "wiki-" in body["logo_url"]
    assert body["logo_url"].endswith(".png")

    db_session.refresh(app)
    assert app.logo_path is not None
    assert "/" not in app.logo_path  # filename only
    assert app.logo_path.startswith("wiki-")
    disk = logos / app.logo_path
    assert disk.is_file()
    with Image.open(disk) as img:
        assert img.size == (128, 128)


def test_app_logo_upload_then_media_get(
    client: TestClient, db_session: Session, logo_dirs
):
    """Regression: upload must land on writable data dir and be served via /media/."""
    _data, logos = logo_dirs
    app = _app(db_session)
    raw = _png_bytes()

    up = client.post(
        f"/admin/apps/{app.id}/logo",
        headers=ADMIN_HEADERS,
        files={"file": ("logo.png", raw, "image/png")},
    )
    assert up.status_code == 200
    logo_url = up.json()["logo_url"]
    filename = logo_url.rsplit("/", 1)[-1]

    get = client.get(logo_url)
    assert get.status_code == 200
    assert get.headers["content-type"].startswith("image/")
    assert len(get.content) > 0
    assert (logos / filename).is_file()
    assert get.content == (logos / filename).read_bytes()


def test_app_logo_upload_rejects_spoofed_extension(
    client: TestClient, db_session: Session, logo_dirs
):
    app = _app(db_session)
    fake = b"not-an-image-but-named-png"
    resp = client.post(
        f"/admin/apps/{app.id}/logo",
        headers=ADMIN_HEADERS,
        files={"file": ("evil.png", fake, "image/png")},
    )
    assert resp.status_code == 400
    assert resp.json()["ok"] is False
    db_session.refresh(app)
    assert app.logo_path is None


def test_app_logo_upload_rejects_svg(
    client: TestClient, db_session: Session, logo_dirs
):
    app = _app(db_session)
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    resp = client.post(
        f"/admin/apps/{app.id}/logo",
        headers=ADMIN_HEADERS,
        files={"file": ("x.svg", svg, "image/svg+xml")},
    )
    assert resp.status_code == 400
    assert "SVG" in resp.json()["detail"]


def test_app_logo_upload_rejects_too_large(
    client: TestClient, db_session: Session, logo_dirs, monkeypatch
):
    monkeypatch.setattr(app_logos, "MAX_LOGO_BYTES", 100)
    app = _app(db_session)
    resp = client.post(
        f"/admin/apps/{app.id}/logo",
        headers=ADMIN_HEADERS,
        files={"file": ("big.png", _png_bytes((200, 200)), "image/png")},
    )
    assert resp.status_code == 400
    assert "512" in resp.json()["detail"] or "Ko" in resp.json()["detail"]


def test_app_logo_delete(client: TestClient, db_session: Session, logo_dirs):
    _data, logos = logo_dirs
    app = _app(db_session)
    up = client.post(
        f"/admin/apps/{app.id}/logo",
        headers=ADMIN_HEADERS,
        files={"file": ("logo.png", _png_bytes(), "image/png")},
    )
    assert up.status_code == 200
    db_session.refresh(app)
    path = logos / app.logo_path
    assert path.is_file()

    resp = client.delete(f"/admin/apps/{app.id}/logo", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    db_session.refresh(app)
    assert app.logo_path is None
    assert not path.exists()


def test_app_logo_fallback_missing_file_on_portal(
    client: TestClient, db_session: Session, logo_dirs
):
    from app.rbac.grants_service import AccessGrantCreate, create_grant

    app = _app(
        db_session,
        description="Wiki interne de l'entreprise",
        logo_path="uploads/app-logos/wiki-deadbeef.png",  # file absent (legacy path ok)
    )
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-user-alice",
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db_session.commit()

    resp = client.get("/apps", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert "Wiki" in resp.text
    assert "Wiki interne de l" in resp.text
    assert "app-tile-menu-desc" in resp.text
    assert "admin-desc" not in resp.text
    assert "app-tile-logo" not in resp.text
    assert "admin-icon" in resp.text
    assert "uploads/app-logos" not in resp.text
    assert "/media/app-logos/" not in resp.text
    assert "deadbeef" not in resp.text
    assert "logo_path" not in resp.text


def test_app_logo_and_description_shown_when_present(
    client: TestClient, db_session: Session, logo_dirs
):
    from app.rbac.grants_service import AccessGrantCreate, create_grant

    app = _app(db_session, description="Transfert de fichiers sécurisé")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-user-alice",
            resource_type="application",
            application_id=app.id,
            access_level="launch",
        ),
        "admin",
    )
    db_session.commit()

    up = client.post(
        f"/admin/apps/{app.id}/logo",
        headers=ADMIN_HEADERS,
        files={"file": ("logo.png", _png_bytes(), "image/png")},
    )
    assert up.status_code == 200
    logo_url = up.json()["logo_url"]
    assert logo_url.startswith("/media/app-logos/")

    resp = client.get("/apps", headers=USER_HEADERS)
    assert resp.status_code == 200
    assert 'src="' + logo_url + '"' in resp.text or f'src="{logo_url}"' in resp.text
    assert "Transfert de fichiers sécurisé" in resp.text
    assert "app-tile-menu-desc" in resp.text
    assert "app-tile-logo" in resp.text
    assert "app-tile--okta" in resp.text

    profile = client.get("/profile", headers=USER_HEADERS)
    assert profile.status_code == 200
    assert "portal-apps-preview-logo" in profile.text
    assert logo_url in profile.text


def test_app_logo_forbidden_for_non_admin(
    client: TestClient, db_session: Session, logo_dirs
):
    app = _app(db_session)
    resp = client.post(
        f"/admin/apps/{app.id}/logo",
        headers=USER_HEADERS,
        files={"file": ("logo.png", _png_bytes(), "image/png")},
        follow_redirects=False,
    )
    # HTML 403 handler redirects non-admins to /apps
    assert resp.status_code in (302, 403)
    db_session.refresh(app)
    assert app.logo_path is None


def test_app_description_saved_on_edit(client: TestClient, db_session: Session):
    app = _app(db_session)
    resp = client.post(
        f"/admin/apps/{app.slug}/edit",
        headers=ADMIN_HEADERS,
        data={
            "label": "Wiki",
            "upstream_url": "https://wiki.example.com/",
            "access_mode": "sso_gate",
            "public_fqdn": "",
            "description": "Base de connaissances partagée",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    db_session.refresh(app)
    assert app.description == "Base de connaissances partagée"


def test_app_edit_redirects_to_apply_wait_then_confirms(
    client: TestClient, db_session: Session, tmp_path, monkeypatch
):
    app = App(
        slug="grommunio",
        label="Grommunio",
        upstream_url="https://10.0.0.9/",
        enabled=True,
        access_mode="subdomain_proxy",
        public_fqdn="webmail.example.fr",
    )
    db_session.add(app)
    db_session.commit()
    db_session.refresh(app)
    monkeypatch.setattr(
        "app.web.pages.export_app_catalogue_files",
        lambda db, settings: {"nginx_subdomain_apps_conf": str(tmp_path / "x.conf")},
    )
    monkeypatch.setattr(
        "app.web.pages.request_host_apply",
        lambda settings, exported_files=0: {"ok": True, "path": str(tmp_path / "apply-infra.request")},
    )
    monkeypatch.setattr(
        "app.web.admin_infrastructure.read_host_apply_status",
        lambda settings, log_max_chars=4000: {
            "status": "ok",
            "status_label": "Appliqué sur l'hôte",
            "badge": "ok",
            "request_pending": False,
            "status_path": str(tmp_path / "apply-infra.status"),
            "log_path": str(tmp_path / "apply-infra.log"),
            "request_path": str(tmp_path / "apply-infra.request"),
            "request_exists": False,
            "log_exists": True,
            "log_text": "done\n",
            "data_dir": str(tmp_path),
        },
    )

    resp = client.post(
        f"/admin/apps/{app.slug}/edit",
        headers=ADMIN_HEADERS,
        data={
            "label": "Grommunio",
            "upstream_url": "https://10.0.0.9/",
            "access_mode": "subdomain_proxy",
            "public_fqdn": "webmail.example.fr",
            "description": "",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "/admin/infrastructure/apply-wait" in (resp.headers.get("location") or "")

    wait = client.get(resp.headers["location"], headers=ADMIN_HEADERS, follow_redirects=False)
    assert wait.status_code == 302
    assert wait.headers.get("location") == "/admin/apps"
    audit = (
        db_session.query(AuditLog)
        .filter_by(action="infrastructure.apply.ok", target=app.slug)
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.details["source"] == "app.updated"


def test_app_edit_stays_on_apply_wait_while_pending(
    client: TestClient, db_session: Session, tmp_path, monkeypatch
):
    app = _app(db_session, slug="grommunio2", label="Grommunio2")
    monkeypatch.setattr("app.web.pages.export_app_catalogue_files", lambda db, settings: {})
    monkeypatch.setattr(
        "app.web.pages.request_host_apply",
        lambda settings, exported_files=0: {"ok": True, "path": str(tmp_path / "apply-infra.request")},
    )
    monkeypatch.setattr(
        "app.web.admin_infrastructure.read_host_apply_status",
        lambda settings, log_max_chars=4000: {
            "status": "pending",
            "status_label": "En attente apply hôte",
            "badge": "warn",
            "request_pending": True,
            "status_path": str(tmp_path / "apply-infra.status"),
            "log_path": str(tmp_path / "apply-infra.log"),
            "request_path": str(tmp_path / "apply-infra.request"),
            "request_exists": True,
            "log_exists": True,
            "log_text": "En attente…\n",
            "data_dir": str(tmp_path),
        },
    )

    resp = client.post(
        f"/admin/apps/{app.slug}/edit",
        headers=ADMIN_HEADERS,
        data={
            "label": "Grommunio2",
            "upstream_url": "https://grommunio2.example.com/",
            "access_mode": "sso_gate",
            "public_fqdn": "",
            "description": "",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    location = resp.headers.get("location") or ""
    assert "/admin/infrastructure/apply-wait" in location

    page = client.get(location, headers=ADMIN_HEADERS, follow_redirects=False)
    assert page.status_code == 200
    assert "Application sur l’hôte en cours" in page.text
    assert "Grommunio2" in page.text
    assert "apply hôte toujours en attente" not in page.text
