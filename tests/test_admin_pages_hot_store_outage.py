"""The configuration page has to load while the hot store is down.

It is the page that carries the hot store panel, so it is where an operator
goes to repair the very outage that would otherwise make it unreachable —
the same trap break-glass fell into on 2026-08-15.
"""

from contextlib import contextmanager
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.db.hot_store import is_hot_model
from app.siem.settings_service import ensure_siem_settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}

PG_DOWN = OperationalError(
    "connect", {}, Exception('password authentication failed for user "bastion_hot"')
)


@contextmanager
def hot_store_down():
    """Every hot-model query fails, as when the Postgres role password drifts.

    Tests bind plain sessions to SQLite, so the outage is injected where the
    routing decision happens rather than by unplugging an engine.
    """
    nominal = Session.get_bind

    def refuse(self, mapper=None, clause=None, bind=None, **kw):
        if mapper is not None and is_hot_model(getattr(mapper, "class_", None)):
            raise PG_DOWN
        return nominal(self, mapper=mapper, clause=clause, bind=bind, **kw)

    with patch.object(Session, "get_bind", refuse):
        yield


def test_page_loads_when_the_hot_store_is_unreachable(
    client: TestClient, db_session: Session
):
    ensure_siem_settings(db_session)

    with hot_store_down():
        page = client.get("/admin/configuration", headers=ADMIN_HEADERS)

    assert page.status_code == 200, "an unreachable hot store must not 500 the page"
    assert "Stockage chaud" in page.text


def test_unknown_queue_size_is_shown_as_unknown(
    client: TestClient, db_session: Session
):
    """Rendering 0 would claim an empty queue we cannot actually see."""
    ensure_siem_settings(db_session)

    with hot_store_down():
        page = client.get("/admin/configuration", headers=ADMIN_HEADERS)

    assert 'File d\'attente :\n        <strong class="mono">None</strong>' not in page.text
    assert "indisponible" in page.text


def test_dashboard_loads_when_the_hot_store_is_unreachable(client: TestClient):
    """Break-glass redirects here, so a 500 would strand the emergency login."""
    with hot_store_down():
        page = client.get("/dashboard", headers=ADMIN_HEADERS)

    assert page.status_code == 200


def test_dashboard_does_not_claim_an_empty_audit_trail(client: TestClient):
    with hot_store_down():
        page = client.get("/dashboard", headers=ADMIN_HEADERS)

    assert "Journal indisponible" in page.text
    assert "Aucune activité récente" not in page.text


def test_logs_page_loads_when_the_hot_store_is_unreachable(client: TestClient):
    with hot_store_down():
        page = client.get("/admin/logs", headers=ADMIN_HEADERS)

    assert page.status_code == 200


def test_logs_page_does_not_claim_an_empty_result(client: TestClient):
    """"Aucune entrée" would read as "nothing happened" during an outage."""
    with hot_store_down():
        page = client.get("/admin/logs", headers=ADMIN_HEADERS)

    assert "Journaux indisponibles" in page.text
    assert "Aucun événement ne correspond aux filtres actuels." not in page.text


def test_sessions_page_loads_when_the_hot_store_is_unreachable(client: TestClient):
    """This page is reachable by any user, not just admins."""
    with hot_store_down():
        page = client.get("/sessions", headers=ADMIN_HEADERS)

    assert page.status_code == 200


def test_sessions_page_does_not_claim_zero_connections(client: TestClient):
    with hot_store_down():
        page = client.get("/sessions", headers=ADMIN_HEADERS)

    assert "Sessions indisponibles" in page.text
    assert 'id="sessions-count">0<' not in page.text
