"""Admin dense screens (UI lot 4): passage line, readable audit, apps list, security and RBAC overviews."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import App, AuditLog
from app.web.metrics_service import humanize_audit_entries
from app.web.passage_series import HOURS, build_passage_series

ADMIN_HEADERS = {"X-Email": "admin@example.com", "X-Groups": "portal-admins"}


def _audit(db: Session, action: str, when: datetime, actor: str = "alice@example.com") -> None:
    db.add(AuditLog(actor=actor, action=action, target="wiki", details={}, created_at=when))


def test_passage_series_buckets_allowed_and_refused_by_hour(db_session: Session):
    now = datetime(2026, 11, 24, 14, 30, tzinfo=timezone.utc)
    _audit(db_session, "app_launch", now - timedelta(minutes=10))  # current hour
    _audit(db_session, "auth.login", now - timedelta(minutes=20))  # current hour
    _audit(db_session, "auth.login_failed", now - timedelta(hours=2, minutes=5))
    _audit(db_session, "admin.app.update", now - timedelta(minutes=5))  # neither
    _audit(db_session, "app_launch", now - timedelta(hours=30))  # outside the window
    db_session.commit()

    series = build_passage_series(db_session, None, now=now)

    assert series["available"] is True
    assert len(series["hours"]) == HOURS
    assert series["hours"][-1]["allowed"] == 2
    assert series["hours"][-3]["refused"] == 1
    assert series["allowed_total"] == 2
    assert series["refused_total"] == 1
    assert series["max"] >= 2


def test_humanize_audit_uses_catalogue_and_folds_repeats():
    entries = [
        {"action": "app_launch", "target": "wiki", "user": "alice", "time": "10:02:00", "event_code": ""},
        {"action": "app_launch", "target": "wiki", "user": "alice", "time": "10:01:00", "event_code": ""},
        {"action": "app_launch", "target": "wiki", "user": "alice", "time": "10:00:00", "event_code": ""},
        {"action": "made.up.action", "target": "", "user": "bob", "time": "09:00:00", "event_code": ""},
    ]
    out = humanize_audit_entries(entries)
    assert len(out) == 2
    assert out[0]["count"] == 3
    assert out[0]["time_first"] == "10:00:00"
    assert out[0]["title"] != "app_launch"
    # Uncatalogued actions keep their raw name rather than a vague placeholder.
    assert out[1]["title"] == "made.up.action"
    assert humanize_audit_entries(None) is None


def test_dashboard_shows_passage_line_instead_of_kpi_tiles(client: TestClient):
    page = client.get("/dashboard", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    assert 'data-dash="gate"' in page.text
    assert "gate-svg" in page.text
    assert "metric-card" not in page.text
    assert 'id="pending-actions"' in page.text


def test_admin_apps_list_moves_delete_into_row_menu(client: TestClient, db_session: Session):
    db_session.add(App(slug="wiki", label="Wiki interne", upstream_url="https://wiki.example.com/", enabled=True))
    db_session.commit()

    page = client.get("/admin/apps", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    html = page.text
    assert "btn-danger" not in html
    assert "row-menu-item--danger" in html
    assert 'data-confirm-typed="wiki"' in html  # typed-slug delete (bastion.js)
    assert 'data-row-href="/admin/apps/wiki/edit"' in html
    assert ">WI<" in html  # monogram, same as the user portal


def test_security_opens_on_state_overview(client: TestClient):
    page = client.get("/admin/security", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    html = page.text
    assert 'id="tab-overview"' in html
    assert "sec-row" in html
    assert ">Misc<" not in html
    assert "var DEFAULT = 'overview'" in html
    assert "'mtls'" in html  # the mTLS panel is reachable by #mtls


def test_rbac_overview_reads_as_sentences(client: TestClient):
    page = client.get("/admin/rbac/overview", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    html = page.text
    assert "rbac-summary-line" in html
    assert "Utils KC" not in html
    assert "breadcrumb-rbac" not in html
