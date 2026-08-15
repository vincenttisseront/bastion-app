"""Admin /admin/logs viewer and request_id middleware tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.parse import urlencode

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import AuditLog, SavedLogView
from app.web.log_masking import mask_secrets, mask_secrets_text

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}
USER_HEADERS = {
    "X-Email": "user@example.com",
    "X-Groups": "transfer-users",
}


def test_logs_rbac_forbidden_for_non_admin(client: TestClient):
    resp = client.get(
        "/admin/logs", headers=USER_HEADERS, follow_redirects=False
    )
    # require_admin → 403; HTML handler redirects authenticated users to /apps.
    assert resp.status_code in (302, 403)
    if resp.status_code == 302:
        assert "/apps" in (resp.headers.get("location") or "")


def test_logs_shows_integrity_and_exports(client: TestClient):
    resp = client.get("/admin/logs", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Intégrité des logs" in resp.text
    assert "export=csv" in resp.text
    assert "export=pdf" in resp.text
    assert "Anomalies de Connexion" not in resp.text

    csv_resp = client.get("/admin/logs?export=csv", headers=ADMIN_HEADERS)
    assert csv_resp.status_code == 200
    assert "text/csv" in (csv_resp.headers.get("content-type") or "")

    audit_redirect = client.get("/audit", headers=ADMIN_HEADERS, follow_redirects=False)
    assert audit_redirect.status_code == 302
    assert "/admin/logs" in (audit_redirect.headers.get("location") or "")


def test_logs_filter_by_action_and_actor(client: TestClient, db_session: Session):
    log_action(db_session, actor="alice@ex.com", action="realm.test", target="r1", details={"status": "ok"})
    log_action(db_session, actor="bob@ex.com", action="health.probe", target="app", details={"status": "warn"})
    log_action(
        db_session,
        actor="alice@ex.com",
        action="credential.set",
        target="transfer",
        details={"password": "SHOULD_NOT_APPEAR", "client_secret": "xyz"},
    )

    resp = client.get("/admin/logs?action=realm.test", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert resp.text.count("data-audit-id=") >= 1
    assert ">realm.test<" in resp.text or "<code>realm.test</code>" in resp.text
    # Filtered table should not list health.probe as a row action (dropdown may still list it)
    assert "<code>health.probe</code>" not in resp.text

    resp2 = client.get("/admin/logs?actor=alice", headers=ADMIN_HEADERS)
    assert resp2.status_code == 200
    assert "alice@ex.com" in resp2.text
    assert "<td" in resp2.text
    # bob should not appear in a data cell as actor for filtered results
    assert resp2.text.count("bob@ex.com") == 0


def test_logs_filter_by_id_deep_link(client: TestClient, db_session: Session):
    a = log_action(
        db_session, actor="admin@example.com", action="breakglass.login", target="admin"
    )
    b = log_action(
        db_session, actor="admin@example.com", action="portal_logout", target="admin"
    )
    assert a.id != b.id

    resp = client.get(f"/admin/logs?id={a.id}", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert f'data-focus-audit-id="{a.id}"' in resp.text
    assert f'data-audit-id="{a.id}"' in resp.text
    assert f'data-audit-id="{b.id}"' not in resp.text
    assert "Entrée #" in resp.text


def test_dashboard_audit_feed_links_to_log(client: TestClient, db_session: Session):
    row = log_action(
        db_session,
        actor="admin@example.com",
        action="breakglass.login",
        target="admin",
    )
    resp = client.get("/dashboard", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert f'href="/admin/logs?id={row.id}#audit"' in resp.text


def test_logs_masks_sensitive_details(client: TestClient, db_session: Session):
    log_action(
        db_session,
        actor="admin@example.com",
        action="realm.create",
        target="demo",
        details={"client_secret": "super-secret-value", "password": "p@ss"},
    )
    resp = client.get("/admin/logs?action=realm.create", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "super-secret-value" not in resp.text
    assert "p@ss" not in resp.text
    assert "***" in resp.text


def test_logs_filter_by_date(client: TestClient, db_session: Session):
    entry = AuditLog(
        actor="admin@example.com",
        action="app.create",
        target="x",
        details={},
        created_at=datetime(2026, 1, 15, tzinfo=timezone.utc),
    )
    db_session.add(entry)
    db_session.commit()

    ok = client.get("/admin/logs?date_from=2026-01-01&date_to=2026-01-31", headers=ADMIN_HEADERS)
    assert ok.status_code == 200
    assert "<code>app.create</code>" in ok.text

    empty = client.get("/admin/logs?date_from=2026-06-01&date_to=2026-06-30", headers=ADMIN_HEADERS)
    assert empty.status_code == 200
    assert "<code>app.create</code>" not in empty.text


def test_logs_combined_filters_status_ip_dates(client: TestClient, db_session: Session):
    match = AuditLog(
        actor="admin@example.com",
        action="breakglass.login_denied_non_lan",
        details={"status": "error", "reason": "breakglass_ip_not_allowed"},
        ip_address="172.24.0.108",
        created_at=datetime(2026, 3, 10, 12, 0, tzinfo=timezone.utc),
    )
    other_ip = AuditLog(
        actor="admin@example.com",
        action="breakglass.login_denied_non_lan",
        details={"status": "error", "reason": "breakglass_ip_not_allowed"},
        ip_address="10.0.0.1",
        created_at=datetime(2026, 3, 10, 12, 5, tzinfo=timezone.utc),
    )
    other_status = AuditLog(
        actor="admin@example.com",
        action="realm.test",
        details={"status": "ok"},
        ip_address="172.24.0.108",
        created_at=datetime(2026, 3, 10, 12, 10, tzinfo=timezone.utc),
    )
    other_date = AuditLog(
        actor="admin@example.com",
        action="breakglass.login_denied_non_lan",
        details={"status": "error"},
        ip_address="172.24.0.108",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    db_session.add_all([match, other_ip, other_status, other_date])
    db_session.commit()

    qs = urlencode(
        [
            ("status", "error"),
            ("ip", "172.24.0.108"),
            ("date_from", "2026-03-01"),
            ("date_to", "2026-03-31"),
        ]
    )
    resp = client.get(f"/admin/logs?{qs}", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert f'data-audit-id="{match.id}"' in resp.text
    assert f'data-audit-id="{other_ip.id}"' not in resp.text
    assert "logs-chip" in resp.text
    assert "Résultat: error" in resp.text
    assert "IP: 172.24.0.108" in resp.text


def test_logs_fulltext_search_in_detail_json(client: TestClient, db_session: Session):
    token = "unique_detail_token_xyz789"
    log_action(
        db_session,
        actor="alice@ex.com",
        action="health.probe",
        details={"nested": {"marker": token}, "status": "ok"},
    )
    log_action(
        db_session,
        actor="bob@ex.com",
        action="realm.test",
        details={"status": "ok", "note": "unrelated"},
    )

    resp = client.get(f"/admin/logs?q={token}", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "alice@ex.com" in resp.text
    assert "bob@ex.com" not in resp.text
    # Token lives only in JSON detail, not as action/actor labels
    assert token in resp.text
    assert resp.text.count("alice@ex.com") >= 1
    assert resp.text.count('<code>health.probe</code>') >= 1
    assert '<code>realm.test</code>' not in resp.text


def test_logs_detail_drawer_replaces_voir_plus(client: TestClient, db_session: Session):
    log_action(
        db_session,
        actor="admin@example.com",
        action="breakglass.login_denied_non_lan",
        details={
            "reason": "breakglass_ip_not_allowed",
            "resolved": None,
            "x_real_ip": "172.24.0.108",
            "x_forwarded_for": "172.24.0.108, 192.168.2.50",
            "peer": "10.5.0.2",
            "note": "long-" + ("n" * 100),
        },
    )
    resp = client.get(
        "/admin/logs?action=breakglass.login_denied_non_lan",
        headers=ADMIN_HEADERS,
    )
    assert 'id="audit-filters"' in resp.text
    assert 'class="logs-filters"' in resp.text or "logs-filters" in resp.text
    assert "logs-filters-row" in resp.text
    assert "logs-filters-grid" in resp.text
    assert 'id="audit-drawer"' in resp.text
    assert 'id="audit-drawer-backdrop"' in resp.text
    assert "data-entry=" in resp.text
    assert "192.168.2.50" in resp.text
    assert "openDrawer" in resp.text or "audit-drawer" in resp.text
    assert "document.body.appendChild" in resp.text
    # No Google Fonts (blocked by edge CSP style-src 'self')
    assert "fonts.googleapis.com" not in resp.text
    # Legacy expand UI removed
    assert "audit-detail-toggle" not in resp.text
    assert "audit-detail-full" not in resp.text
    tbody_start = resp.text.index('id="audit-tbody"')
    tbody_end = resp.text.index("</tbody>", tbody_start)
    tbody = resp.text[tbody_start:tbody_end]
    assert "<details" not in tbody
    assert "voir plus" not in tbody.lower()
    assert "voir moins" not in tbody.lower()


def test_logs_saved_view_roundtrip(client: TestClient, db_session: Session):
    log_action(
        db_session,
        actor="alice@ex.com",
        action="realm.test",
        details={"status": "error", "reason": "boom"},
        ip_address="172.24.0.50",
    )
    log_action(
        db_session,
        actor="bob@ex.com",
        action="health.probe",
        details={"status": "ok"},
        ip_address="10.0.0.1",
    )

    filters = {
        "action": "realm.test",
        "actor": "alice",
        "date_from": "",
        "date_to": "",
        "ip": "172.24.0.50",
        "q": "",
        "detail": "boom",
        "status": ["error"],
    }
    columns = "timestamp,actor,action,ip,result,detail,reason"
    save = client.post(
        "/admin/logs/views",
        headers=ADMIN_HEADERS,
        data={
            "name": "Erreurs Alice",
            "filters_json": json.dumps(filters),
            "columns": columns,
        },
        follow_redirects=False,
    )
    assert save.status_code == 302

    view = (
        db_session.query(SavedLogView)
        .filter_by(user_email="admin@example.com", name="Erreurs Alice")
        .one()
    )
    assert view.filters_json["ip"] == "172.24.0.50"
    assert view.filters_json["status"] == ["error"]
    assert "reason" in view.columns_json

    applied = client.get(f"/admin/logs?view={view.id}", headers=ADMIN_HEADERS)
    assert applied.status_code == 200
    assert f'data-audit-id="' in applied.text
    assert "alice@ex.com" in applied.text
    assert "bob@ex.com" not in applied.text
    assert 'name="detail"' in applied.text and 'value="boom"' in applied.text
    assert "Erreurs Alice" in applied.text
    assert ">reason<" in applied.text or "reason" in applied.text
    assert "Sécurité" in applied.text  # system default view seeded


def test_logs_columns_prefs_persist(client: TestClient, db_session: Session):
    save = client.post(
        "/admin/logs/prefs/columns",
        headers=ADMIN_HEADERS,
        data={"columns": "timestamp,action,reason,peer"},
        follow_redirects=False,
    )
    assert save.status_code == 302

    page = client.get("/admin/logs", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    assert 'data-columns="timestamp,action,reason,peer"' in page.text
    assert "<th>reason</th>" in page.text
    assert "<th>peer</th>" in page.text


def test_miss_family_is_a_selectable_column(client: TestClient, db_session: Session):
    """Reading the ActiveSync switchover criterion must not require raw SQL.

    The unidentified-device families drive opposite decisions, so they have to be
    groupable from the audit view itself.
    """
    log_action(
        db_session,
        actor="phone@ex.com",
        action="activesync.device_unidentified",
        details={"miss_reason": "base64_truncated", "miss_family": "decoder_failure"},
    )
    save = client.post(
        "/admin/logs/prefs/columns",
        headers=ADMIN_HEADERS,
        data={"columns": "timestamp,action,miss_family"},
        follow_redirects=False,
    )
    assert save.status_code == 302

    page = client.get(
        "/admin/logs?action=activesync.device_unidentified", headers=ADMIN_HEADERS
    )
    assert "<th>miss_family</th>" in page.text
    assert "decoder_failure" in page.text


def test_mask_secrets_helpers():
    assert mask_secrets({"password": "x", "ok": True}) == {"password": "***", "ok": True}
    assert "secret=***" in mask_secrets_text("client_secret=abc123 rest")


def test_format_details_expand_shows_more_than_preview():
    from app.web.log_masking import format_details_for_display

    details = {
        "reason": "breakglass_ip_not_allowed",
        "resolved": None,
        "x_real_ip": "172.24.0.108",
        "x_forwarded_for": "172.24.0.108, 10.5.0.12",
        "peer": "10.5.0.2",
        "extra": "padding-" + ("x" * 80),
    }
    short, full = format_details_for_display(details, max_len=80)
    assert "{" not in short  # compact label, not raw JSON dump
    assert "breakglass_ip_not_allowed" in short
    assert "champs" in short
    assert short != full
    assert "x_forwarded_for" in full
    assert "10.5.0.12" in full
    assert "\n" in full  # pretty-printed


def test_format_details_short_has_no_expand_pair():
    from app.web.log_masking import format_details_for_display

    short, full = format_details_for_display({"error": "url_blocked", "forms_found": 0})
    assert "url_blocked" in short
    assert "{" not in short
    assert "url_blocked" in full
    assert "\n" in full


def test_format_details_app_launch_shows_target_and_label():
    from app.web.log_masking import format_details_for_display, summarize_details_for_table

    details = {
        "application_id": 12,
        "app_slug": "wikijs",
        "app_label": "Wiki.js",
        "access_level": "Launch",
        "sources": ["via groupe ARSYSTEMS-Users"],
        "grant_ids": [12],
    }
    label = summarize_details_for_table(details)
    assert "Wiki.js" in label
    assert "Launch" in label
    short, full = format_details_for_display(details, target="wikijs", action="app_launch")
    assert "Wiki.js" in short
    assert "wikijs" in short
    assert "Launch" in short
    assert "application_id" in full


def test_summarize_session_hijack_detail():
    from app.web.log_masking import format_details_for_display, summarize_details_for_table

    details = {
        "family": "sso",
        "cookie_hash_prefix": "75bdc892e5335867",
        "username": "e189ed16-79f0-4fa1-85ee-1bb7ff28052c",
        "expected_subnet": "192.168.2.0/24",
        "observed_subnet": "10.0.0.0/8",
        "policy": "stepup_401",
    }
    label = summarize_details_for_table(details)
    assert "sso" in label
    assert "75bdc892e5335867" not in label  # hash not dumped in table
    assert "{" not in label
    short, full = format_details_for_display(details)
    assert short == label
    assert "75bdc892e5335867" in full
    assert '"family": "sso"' in full


def test_logs_detail_column_is_compact_not_json_dump(client: TestClient, db_session: Session):
    import re

    log_action(
        db_session,
        actor="admin@example.com",
        action="session_hijack_suspected",
        details={
            "family": "sso",
            "cookie_hash_prefix": "75bdc892e5335867",
            "username": "e189ed16-79f0-4fa1-85ee-1bb7ff28052c",
            "expected_subnet": "192.168.2.0/24",
            "observed_subnet": "10.0.0.0/8",
            "policy": "stepup_401",
        },
    )
    resp = client.get(
        "/admin/logs?action=session_hijack_suspected",
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 200
    tbody_start = resp.text.index('id="audit-tbody"')
    tbody_end = resp.text.index("</tbody>", tbody_start)
    tbody = resp.text[tbody_start:tbody_end]
    assert "audit-detail-summary" in tbody
    assert "audit-detail-open" in tbody
    m = re.search(r'class="audit-detail-summary">([^<]*)', tbody)
    assert m, "missing compact detail summary"
    summary = m.group(1)
    assert "{" not in summary
    assert "sso" in summary
    assert "75bdc892e5335867" not in summary
    # Full JSON still available for drawer via data-entry
    assert "75bdc892e5335867" in tbody
    assert 'id="audit-drawer"' in resp.text


def test_request_id_header_present_and_unique(client: TestClient):
    r1 = client.get("/api/health")
    r2 = client.get("/api/health")
    assert "x-request-id" in {k.lower() for k in r1.headers.keys()}
    id1 = r1.headers.get("x-request-id") or r1.headers.get("X-Request-Id")
    id2 = r2.headers.get("x-request-id") or r2.headers.get("X-Request-Id")
    assert id1
    assert id2
    assert id1 != id2


def test_request_id_propagates_incoming(client: TestClient):
    resp = client.get("/api/health", headers={"X-Request-Id": "fixed-correlation-id"})
    assert resp.headers.get("x-request-id") == "fixed-correlation-id"
