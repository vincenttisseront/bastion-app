"""Public error pages show company_name — no Bastion Pro by default."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.branding import update_branding_settings


def test_error_pages_neutral(client: TestClient, db_session: Session):
    update_branding_settings(
        db_session,
        actor="test",
        company_name="Portail ACME",
        show_product_branding=False,
    )
    for path, code in (
        ("/errors/403", 403),
        ("/errors/400", 400),
        ("/errors/404", 404),
        ("/errors/429", 429),
        ("/errors/500", 500),
        ("/errors/503", 503),
    ):
        r = client.get(path)
        assert r.status_code == code
        assert "Portail ACME" in r.text
        assert "Bastion Pro" not in r.text
        assert "/static/portal.css" in r.text
        assert "bastion.css" not in r.text


def test_error_pages_product_opt_in(client: TestClient, db_session: Session):
    update_branding_settings(
        db_session,
        actor="test",
        show_product_branding=True,
    )
    r = client.get("/errors/404")
    assert r.status_code == 404
    # Title suffix when product branding enabled
    assert "Bastion Pro" in r.text
