"""The Configuration panel must say which password the application uses.

Checking "the same password" in the admin form while the code reads the
environment variable is how the 2026-08-15 outage stayed puzzling: both values
looked right, only one was in play.
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.hot_store import (
    PASSWORD_SOURCE_ENV,
    PASSWORD_SOURCE_NONE,
    PASSWORD_SOURCE_STORED,
    get_hot_store_status,
    password_fingerprint,
)
from app.portal_settings_service import ensure_portal_settings
from app.secret_crypto import encrypt_secret
from app.sso_settings import get_settings

ADMIN_HEADERS = {"X-Email": "admin@example.com", "X-Groups": "portal-admins"}


def _env_password(monkeypatch, value: str):
    """Set it where Settings reads it: the request builds its own instance."""
    if value:
        monkeypatch.setenv("HOT_STORE_PG_PASSWORD", value)
    else:
        monkeypatch.delenv("HOT_STORE_PG_PASSWORD", raising=False)
    get_settings.cache_clear()
    return get_settings()


def _configure(db: Session, settings, *, stored: str | None = None):
    row = ensure_portal_settings(db, settings)
    row.hot_store_host = "postgres"
    row.hot_store_port = 5432
    row.hot_store_database = "bastion_hot"
    row.hot_store_user = "bastion_hot"
    row.hot_store_password_encrypted = (
        encrypt_secret(stored, settings) if stored else None
    )
    db.commit()
    return row


def test_fingerprint_does_not_carry_the_password():
    fp = password_fingerprint("hunter2-hunter2", key="deployment-key")
    assert "hunter2" not in fp
    assert len(fp) == 8


def test_fingerprint_is_keyed_to_the_deployment():
    """A bare digest of a weak password is guessable offline; this page is not."""
    one = password_fingerprint("same-password", key="key-a")
    two = password_fingerprint("same-password", key="key-b")
    assert one != two


def test_fingerprint_still_compares_two_values_under_one_key():
    key = "deployment-key"
    assert password_fingerprint("a", key=key) == password_fingerprint("a", key=key)
    assert password_fingerprint("a", key=key) != password_fingerprint("b", key=key)


def test_empty_password_has_no_fingerprint():
    assert password_fingerprint("", key="k") == ""


def test_environment_is_reported_as_the_source_in_use(db_session: Session, monkeypatch):
    settings = _env_password(monkeypatch, "env-value")
    _configure(db_session, settings, stored="stored-value")

    status = get_hot_store_status(db_session, settings)

    assert status.password_source == PASSWORD_SOURCE_ENV
    assert status.password_sources_agree is False


def test_stored_is_the_source_when_the_variable_is_absent(
    db_session: Session, monkeypatch
):
    settings = _env_password(monkeypatch, "")
    _configure(db_session, settings, stored="stored-value")

    status = get_hot_store_status(db_session, settings)

    assert status.password_source == PASSWORD_SOURCE_STORED
    assert status.env_password_fingerprint == ""
    assert status.password_sources_agree is None


def test_matching_values_are_reported_as_agreeing(db_session: Session, monkeypatch):
    settings = _env_password(monkeypatch, "same-value")
    _configure(db_session, settings, stored="same-value")

    status = get_hot_store_status(db_session, settings)

    assert status.password_sources_agree is True


def test_no_password_at_all(db_session: Session, monkeypatch):
    settings = _env_password(monkeypatch, "")
    _configure(db_session, settings, stored=None)

    assert get_hot_store_status(db_session, settings).password_source == (
        PASSWORD_SOURCE_NONE
    )


def test_panel_names_the_source_and_warns_on_divergence(
    client: TestClient, db_session: Session, monkeypatch
):
    settings = _env_password(monkeypatch, "env-value")
    _configure(db_session, settings, stored="stored-value")

    page = client.get("/admin/configuration", headers=ADMIN_HEADERS)

    assert page.status_code == 200
    assert "Variable HOT_STORE_PG_PASSWORD" in page.text
    assert "Les deux valeurs diffèrent" in page.text
    assert "env-value" not in page.text, "le secret ne doit pas être rendu"
    assert "stored-value" not in page.text


def test_panel_warns_when_the_variable_is_missing(
    client: TestClient, db_session: Session, monkeypatch
):
    settings = _env_password(monkeypatch, "")
    _configure(db_session, settings, stored="stored-value")

    page = client.get("/admin/configuration", headers=ADMIN_HEADERS)

    assert "Valeur enregistrée en base" in page.text
    assert "vont diverger au prochain redémarrage" in page.text
