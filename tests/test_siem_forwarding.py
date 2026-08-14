"""SIEM formatting, outbox, transport, and filter tests."""

from __future__ import annotations

import json
from datetime import timedelta

import httpx
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import AuditLog, SiemOutboxEntry, utcnow
from app.siem.formatters import cef_severity, format_cef, format_ecs
from app.siem.outbox import process_outbox_once, queue_size
from app.siem.settings_service import (
    action_passes_filter,
    ensure_siem_settings,
    get_siem_config,
    update_siem_settings,
)
from app.siem.transport import SiemDeliveryError, deliver_entry
from app.sso_settings import get_settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _sample_entry(**overrides):
    base = {
        "id": 42,
        "action": "session_hijack_suspected",
        "actor": "e189ed16-79f0-4fa1-85ee-1bb7ff28052c",
        "target": "75bdc892e5335867",
        "ip_address": "192.168.2.172",
        "severity": "error",
        "status": None,
        "result": "error",
        "detail_short": "sso",
        "detail_full": '{\n  "family": "sso",\n  "cookie_hash_prefix": "75bdc892e5335867"\n}',
        "detail": {"family": "sso", "cookie_hash_prefix": "75bdc892e5335867"},
        "extras": {},
        "timestamp": "2026-07-26 12:12:05 UTC",
    }
    base.update(overrides)
    return base


def test_cef_format_and_escape():
    entry = _sample_entry(
        action="breakglass.login_failed",
        event_code="BST-BGL-2001",
        event_label="BREAKGLASS_LOGIN_FAILED",
        catalog_severity="WARNING",
        result="error",
    )
    cef = format_cef(entry, version="0.5.0")
    assert cef.startswith("CEF:0|iBanFirst|BastionPro-Sentinel|0.5.0|")
    assert "BST-BGL-2001" in cef
    assert "BREAKGLASS_LOGIN_FAILED" in cef
    assert "outcome=error" in cef
    assert cef_severity(entry) == 5  # WARNING
    # Historical result-only fallback (no code)
    assert cef_severity("error") == 7
    assert cef_severity("success") == 3  # NOTICE
    assert cef_severity("info") == 1  # INFO


def test_cef_critical_success_is_severity_10():
    """Decisive case: success result + CRITICAL catalogue → CEF 10, not 1."""
    entry = _sample_entry(
        action="breakglass.login",
        result="success",
        event_code="BST-BGL-4001",
        event_label="BREAKGLASS_LOGIN_FROM_NON_LAN",
        catalog_severity="CRITICAL",
        domain="BGL",
    )
    cef = format_cef(entry)
    assert "|10|" in cef or cef.split("|")[6] == "10"
    assert "BST-BGL-4001" in cef
    assert cef_severity(entry) == 10


def test_cef_truncation_marker():
    big = {"blob": "x" * 8000}
    entry = _sample_entry(detail=big, detail_full=json.dumps(big), result="info")
    cef = format_cef(entry)
    assert "truncated" in cef
    assert "…[truncated]" in cef or "cs2=true" in cef


def test_ecs_json_full_detail():
    entry = _sample_entry(
        event_code="BST-SESS-4001",
        event_label="SESSION_HIJACK_SUSPECTED",
        catalog_severity="CRITICAL",
        ecs_category=["session", "intrusion_detection"],
        domain="SESS",
    )
    doc = format_ecs(entry, version="0.5.0")
    assert doc["@timestamp"] == "2026-07-26T12:12:05Z"
    assert doc["event"]["code"] == "BST-SESS-4001"
    assert doc["event"]["action"] == "SESSION_HIJACK_SUSPECTED"
    assert doc["event"]["outcome"] == "error"
    assert doc["event"]["severity"] == 10
    assert doc["log"]["level"] == "critical"
    assert doc["user"]["name"] == "e189ed16-79f0-4fa1-85ee-1bb7ff28052c"
    assert doc["source"]["ip"] == "192.168.2.172"
    assert doc["bastion"]["detail"]["cookie_hash_prefix"] == "75bdc892e5335867"
    assert doc["observer"]["vendor"] == "iBanFirst"
    assert doc["observer"]["product"] == "BastionPro-Sentinel"


def test_filter_allow_deny():
    ensure = ensure_siem_settings
    # unit on config object
    from app.siem.settings_service import SiemForwardingConfig

    deny = SiemForwardingConfig(
        enabled=True,
        protocol="webhook_https",
        syslog_host="",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="https://example.test/h",
        webhook_auth_type="none",
        webhook_auth_configured=False,
        filter_mode="denylist",
        filter_actions=["health.probe"],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        last_success_at=None,
    )
    assert action_passes_filter(deny, "realm.test")
    assert not action_passes_filter(deny, "health.probe")
    assert not action_passes_filter(deny, "siem.forward.dropped")

    allow = SiemForwardingConfig(
        enabled=True,
        protocol="webhook_https",
        syslog_host="",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="https://example.test/h",
        webhook_auth_type="none",
        webhook_auth_configured=False,
        filter_mode="allowlist",
        filter_actions=["realm.test"],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        last_success_at=None,
    )
    assert action_passes_filter(allow, "realm.test")
    assert not action_passes_filter(allow, "health.probe")


def test_filter_domain_glob_and_severity():
    from app.siem.settings_service import SiemForwardingConfig, event_passes_filter

    deny = SiemForwardingConfig(
        enabled=True,
        protocol="webhook_https",
        syslog_host="",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="https://example.test/h",
        webhook_auth_type="none",
        webhook_auth_configured=False,
        filter_mode="denylist",
        filter_actions=["BST-WAF-*"],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        last_success_at=None,
    )
    assert not event_passes_filter(
        deny,
        action="security.ban.applied",
        event_code="BST-WAF-4001",
        catalog_severity="CRITICAL",
        domain="WAF",
    )
    assert event_passes_filter(
        deny,
        action="realm.test",
        event_code="BST-ADM-1017",
        catalog_severity="NOTICE",
        domain="ADM",
    )

    allow = SiemForwardingConfig(
        enabled=True,
        protocol="webhook_https",
        syslog_host="",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="https://example.test/h",
        webhook_auth_type="none",
        webhook_auth_configured=False,
        filter_mode="allowlist",
        filter_actions=["severity>=ERROR"],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        last_success_at=None,
    )
    assert event_passes_filter(
        allow,
        action="security.ban.applied",
        event_code="BST-WAF-4001",
        catalog_severity="CRITICAL",
        domain="WAF",
    )
    assert not event_passes_filter(
        allow,
        action="admin.container_logs.viewed",
        event_code="BST-ADM-0001",
        catalog_severity="INFO",
        domain="ADM",
    )


def test_webhook_delivery_mock(httpx_mock=None):
    cfg = get_siem_config  # placate linters
    from app.siem.settings_service import SiemForwardingConfig

    config = SiemForwardingConfig(
        enabled=True,
        protocol="webhook_https",
        syslog_host="",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="https://siem.test/ingest",
        webhook_auth_type="bearer",
        webhook_auth_configured=True,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        last_success_at=None,
    )
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"ok": True})
    )
    with httpx.Client(transport=transport) as client:
        deliver_entry(
            _sample_entry(),
            config,
            secret="tok-secret",
            http_client=client,
        )


def test_syslog_tls_delivery_mock():
    from app.siem.settings_service import SiemForwardingConfig

    config = SiemForwardingConfig(
        enabled=True,
        protocol="syslog_tls",
        syslog_host="siem.test",
        syslog_port=6514,
        syslog_tls_verify=False,
        webhook_url="",
        webhook_auth_type="none",
        webhook_auth_configured=False,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        last_success_at=None,
    )
    sent = []

    class FakeSock:
        def sendall(self, data):
            sent.append(data)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    deliver_entry(_sample_entry(), config, sock_factory=lambda: FakeSock())
    assert sent
    assert b"CEF:0|" in sent[0]


def test_outbox_retry_then_success(db_session: Session, monkeypatch):
    settings = get_settings()
    update_siem_settings(
        db_session,
        settings,
        enabled=True,
        protocol="webhook_https",
        syslog_host="",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="https://siem.test/ingest",
        webhook_auth_type="none",
        webhook_auth_secret=None,
        clear_webhook_secret=False,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        actor="admin@example.com",
    )
    entry = log_action(
        db_session,
        actor="alice@ex.com",
        action="realm.test",
        details={"status": "ok"},
    )
    assert entry is not None
    assert queue_size(db_session) >= 1

    calls = {"n": 0}

    def flaky_deliver(payload, cfg, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise SiemDeliveryError("down")
        return None

    monkeypatch.setattr("app.siem.outbox.deliver_entry", flaky_deliver)
    stats1 = process_outbox_once(db_session, settings)
    assert stats1["failed"] >= 1
    assert queue_size(db_session) >= 1
    # Force due now
    for row in db_session.query(SiemOutboxEntry).all():
        row.next_attempt_at = utcnow() - timedelta(seconds=1)
    db_session.commit()
    stats2 = process_outbox_once(db_session, settings)
    assert stats2["sent"] >= 1
    assert queue_size(db_session) == 0


def test_outbox_purge_max_age_audits(db_session: Session):
    settings = get_settings()
    update_siem_settings(
        db_session,
        settings,
        enabled=True,
        protocol="webhook_https",
        syslog_host="",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="https://siem.test/ingest",
        webhook_auth_type="none",
        webhook_auth_secret=None,
        clear_webhook_secret=False,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=100,
        retry_max_age_minutes=1,
        actor="admin@example.com",
    )
    entry = log_action(
        db_session, actor="a", action="realm.old", details={"x": 1}
    )
    assert entry
    row = db_session.query(SiemOutboxEntry).filter_by(audit_log_id=entry.id).one()
    row.created_at = utcnow() - timedelta(minutes=10)
    db_session.commit()

    # Avoid actual network: mark not active by clearing URL temporarily via process with disabled delivery
    # process_outbox purges before checking active... purge_stale runs even when enabled
    stats = process_outbox_once(db_session, settings)
    assert stats["purged"] >= 1
    dropped = (
        db_session.query(AuditLog)
        .filter_by(action="siem.forward.dropped")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert dropped is not None
    assert dropped.details.get("reason") == "max_age"


def test_queue_full_drops_with_audit(db_session: Session):
    settings = get_settings()
    update_siem_settings(
        db_session,
        settings,
        enabled=True,
        protocol="webhook_https",
        syslog_host="",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="https://siem.test/ingest",
        webhook_auth_type="none",
        webhook_auth_secret=None,
        clear_webhook_secret=False,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=2,
        retry_max_age_minutes=60,
        actor="admin@example.com",
    )
    log_action(db_session, actor="a", action="realm.a", details={})
    log_action(db_session, actor="a", action="realm.b", details={})
    log_action(db_session, actor="a", action="realm.c", details={})
    assert queue_size(db_session) == 2
    dropped = db_session.query(AuditLog).filter_by(action="siem.forward.dropped").count()
    assert dropped >= 1


def test_connectivity_test_button(client: TestClient, db_session: Session, monkeypatch):
    settings = get_settings()
    update_siem_settings(
        db_session,
        settings,
        enabled=True,
        protocol="webhook_https",
        syslog_host="",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="https://siem.test/ingest",
        webhook_auth_type="none",
        webhook_auth_secret=None,
        clear_webhook_secret=False,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        actor="admin@example.com",
    )

    monkeypatch.setattr(
        "app.siem.outbox.deliver_entry",
        lambda *a, **k: None,
    )
    resp = client.post(
        "/admin/configuration/siem/test",
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    page = client.get("/admin/configuration", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    assert 'id="configuration-tabs"' in page.text
    assert 'id="siem"' in page.text
    assert "Forwarding SIEM" in page.text
    assert 'id="smtp"' in page.text
    assert 'action="/admin/configuration/smtp/test"' in page.text
    assert 'id="siem-test-btn"' in page.text
    assert 'id="siem-test-shell"' in page.text


def test_connectivity_test_json_shell_transcript(
    client: TestClient, db_session: Session, monkeypatch
):
    settings = get_settings()
    update_siem_settings(
        db_session,
        settings,
        enabled=True,
        protocol="webhook_https",
        syslog_host="",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="https://siem.test/ingest",
        webhook_auth_type="none",
        webhook_auth_secret=None,
        clear_webhook_secret=False,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        actor="admin@example.com",
    )
    monkeypatch.setattr("app.siem.outbox.deliver_entry", lambda *a, **k: None)
    resp = client.post(
        "/admin/configuration/siem/test",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert "OK" in data["message"]
    assert any(line.startswith("$ bastion siem") for line in data["lines"])
    assert any(line.startswith("→ POST https://siem.test/ingest") for line in data["lines"])
    assert any(line.startswith("✓") for line in data["lines"])
    assert any("event.code=BST-SIEM-0001" in line for line in data["lines"])


def test_connectivity_test_json_failure(client: TestClient, db_session: Session):
    ensure_siem_settings(db_session)
    resp = client.post(
        "/admin/configuration/siem/test",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["ok"] is False
    assert any("désactivé" in line.lower() or line.startswith("✗") for line in data["lines"])


def test_siem_disabled_by_default_no_enqueue(db_session: Session):
    ensure_siem_settings(db_session)
    cfg = get_siem_config(db_session)
    assert cfg.enabled is False
    before = queue_size(db_session)
    log_action(db_session, actor="a", action="realm.test", details={})
    assert queue_size(db_session) == before


def test_live_non_regression_still_lists_logs(client: TestClient, db_session: Session):
    log_action(db_session, actor="alice@ex.com", action="realm.test", details={"status": "ok"})
    resp = client.get("/admin/logs?action=realm.test", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert 'id="audit-live-btn"' in resp.text
    assert "<code>realm.test</code>" in resp.text
