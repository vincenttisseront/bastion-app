"""Realigning the PostgreSQL role from the Configuration panel.

The entrypoint only re-applies the password when the postgres container is
created, and `docker compose restart` does not re-read .env — so a correct .env
can sit next to a stale container indefinitely. The button reuses the existing
apply-infra signal, whose host script ends with `docker compose up -d`.
"""

from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import AuditLog
from app.portal_settings_service import ensure_portal_settings
from app.sso_settings import Settings, get_settings

ADMIN_HEADERS = {"X-Email": "admin@example.com", "X-Groups": "portal-admins"}


def _settings(tmp_path) -> Settings:
    data = tmp_path / "data"
    exports = data / "exports"
    exports.mkdir(parents=True)
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        exports_dir=str(exports),
        portal_data_dir=str(data),
    )


def _configure_hot_store(db: Session, settings: Settings):
    row = ensure_portal_settings(db, settings)
    row.hot_store_host = "postgres"
    row.hot_store_port = 5432
    row.hot_store_database = "bastion_hot"
    row.hot_store_user = "bastion_hot"
    db.commit()


def test_button_writes_the_host_signal(
    client: TestClient, db_session: Session, tmp_path
):
    settings = _settings(tmp_path)
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings

    response = client.post(
        "/admin/configuration/hot-store/realign",
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "/admin/infrastructure/apply-wait" in response.headers["location"]
    assert (Path(settings.portal_data_dir) / "apply-infra.request").is_file()


def test_the_request_is_audited(client: TestClient, db_session: Session, tmp_path):
    settings = _settings(tmp_path)
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings

    client.post(
        "/admin/configuration/hot-store/realign",
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )

    entry = (
        db_session.query(AuditLog)
        .filter_by(action="hot_store.realign_requested")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert entry is not None
    assert entry.target == "postgres"


def test_the_action_is_catalogued():
    """An uncatalogued action lands as -0000 and escapes severity routing."""
    from app.audit.event_catalog import resolve_event

    event = resolve_event(action="hot_store.realign_requested")
    assert event.code == "BST-SYS-1010"
    assert event.label == "HOT_STORE_REALIGN_REQUESTED"


def test_panel_offers_the_button_once_configured(
    client: TestClient, db_session: Session, tmp_path
):
    settings = _settings(tmp_path)
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings
    _configure_hot_store(db_session, settings)

    page = client.get("/admin/configuration", headers=ADMIN_HEADERS)

    assert 'action="/admin/configuration/hot-store/realign"' in page.text
    assert "Réaligner le rôle PostgreSQL" in page.text


def test_button_is_absent_before_any_configuration(
    client: TestClient, db_session: Session, tmp_path
):
    """Nothing to realign yet — the button would only mislead."""
    settings = _settings(tmp_path)
    get_settings.cache_clear()
    client.app.dependency_overrides[get_settings] = lambda: settings

    page = client.get("/admin/configuration", headers=ADMIN_HEADERS)

    assert 'action="/admin/configuration/hot-store/realign"' not in page.text
