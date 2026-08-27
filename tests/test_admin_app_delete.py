"""Admin hard-delete of catalogue applications."""

from __future__ import annotations

from unittest.mock import patch

from sqlalchemy.orm import Session

from app.models import AccessGrant, App, AppCredential, RBACGroup

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Preferred-Username": "admin",
    "X-Groups": "portal-admins",
    "X-Portal-Realm-Slug": "ar-systems",
}


def _app(db: Session, *, slug: str = "mantis") -> App:
    app = App(
        slug=slug,
        label="Mantis",
        upstream_url="https://10.0.31.112/",
        access_mode="subdomain_proxy",
        public_fqdn=f"{slug}.example.fr",
        enabled=True,
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def test_admin_delete_app_removes_row_and_grants(client, db_session: Session):
    app = _app(db_session)
    group = RBACGroup(name="ops", path="/ops")
    db_session.add(group)
    db_session.commit()
    db_session.refresh(group)
    db_session.add(
        AccessGrant(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="application",
            application_id=app.id,
            access_level="view",
            granted_by="admin@example.com",
        )
    )
    db_session.add(
        AppCredential(
            app_slug=app.slug,
            robotic_username="bot",
            encrypted_password="cipher",
        )
    )
    db_session.commit()

    with (
        patch("app.web.pages.export_app_catalogue_files", return_value={"a": "1"}),
        patch(
            "app.web.pages.request_host_apply",
            return_value={"ok": True, "message": "signaled"},
        ),
        patch(
            "app.web.pages.host_apply_wait_redirect",
            side_effect=lambda **kwargs: __import__(
                "fastapi.responses", fromlist=["RedirectResponse"]
            ).RedirectResponse(url=kwargs["next_path"], status_code=302),
        ),
    ):
        resp = client.post(
            f"/admin/apps/{app.slug}/delete",
            headers=ADMIN_HEADERS,
            follow_redirects=False,
        )
    assert resp.status_code in (302, 303)
    assert resp.headers["location"] == "/admin/apps"
    assert db_session.query(App).filter_by(slug="mantis").first() is None
    assert db_session.query(AccessGrant).count() == 0
    assert db_session.query(AppCredential).count() == 0


def test_admin_delete_app_missing_404(client, db_session: Session):
    resp = client.post(
        "/admin/apps/does-not-exist/delete",
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 404
