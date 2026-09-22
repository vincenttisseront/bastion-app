"""Unit coverage for S3776 helper extractions in batch7."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import Response

from app.admin.export import _prune_stale_oauth2_conf, _prune_stale_oauth2_dirs
from app.admin.rbac_accounts import (
    _flash_reset_password_outcome,
    _want_send_email,
)
from app.admin.rbac_governance import _apply_group_meta_updates, _mode_is_total
from app.rbac.account_service import (
    AccountCreationError,
    _validate_new_bastion_account_inputs,
)
from app.rbac.governance_service import _aware_dt, _excess_perm_alert_line


def test_want_send_email_truthy_values():
    assert _want_send_email("1")
    assert _want_send_email("TRUE")
    assert _want_send_email("on")
    assert not _want_send_email("")
    assert not _want_send_email("0")


def test_flash_reset_password_outcome_branches(monkeypatch):
    calls: list[tuple] = []

    def _fake_flash(response, msg, level, secret):
        calls.append((msg, level, secret))

    monkeypatch.setattr(
        "app.admin.rbac_accounts.flash_redirect", _fake_flash
    )
    resp = Response()
    _flash_reset_password_outcome(
        resp,
        want_email=True,
        email_error="smtp down",
        secret="dev",
        emailed_ok_msg="ok-mail",
        no_email_msg="no-mail",
    )
    assert calls[-1][1] == "warning"
    _flash_reset_password_outcome(
        resp,
        want_email=True,
        email_error=None,
        secret="dev",
        emailed_ok_msg="ok-mail",
        no_email_msg="no-mail",
    )
    assert calls[-1] == ("ok-mail", "success", "dev")
    _flash_reset_password_outcome(
        resp,
        want_email=False,
        email_error=None,
        secret="dev",
        emailed_ok_msg="ok-mail",
        no_email_msg="no-mail",
    )
    assert calls[-1] == ("no-mail", "success", "dev")


def test_mode_is_total_and_group_meta():
    assert _mode_is_total("total")
    assert _mode_is_total("acces_total")
    assert not _mode_is_total("limited")
    group = SimpleNamespace(description="old", group_tag="t")
    _apply_group_meta_updates(group, {"description": "  ", "group_tag": "ops"})
    assert group.description is None
    assert group.group_tag == "ops"


def test_prune_stale_oauth2_helpers(tmp_path: Path):
    (tmp_path / "oauth2-proxy-gone.conf").write_text("x", encoding="utf-8")
    (tmp_path / "oauth2-proxy-keep.conf").write_text("y", encoding="utf-8")
    removed = _prune_stale_oauth2_conf(tmp_path, {"keep"})
    assert any("gone" in p for p in removed)
    assert (tmp_path / "oauth2-proxy-keep.conf").is_file()

    oauth2 = tmp_path / "oauth2"
    stale = oauth2 / "stale"
    stale.mkdir(parents=True)
    (stale / "cookie").write_text("z", encoding="utf-8")
    (oauth2 / "keep").mkdir()
    removed_dirs = _prune_stale_oauth2_dirs(tmp_path, {"keep"})
    assert any("stale" in p for p in removed_dirs)
    assert (oauth2 / "keep").is_dir()


def test_excess_perm_alert_line_and_aware():
    naive = datetime(2020, 1, 1, 12, 0, 0)
    aware = _aware_dt(naive)
    assert aware.tzinfo is not None
    assert _aware_dt(None) is None

    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    old = SimpleNamespace(
        can_write=True,
        can_delete=False,
        updated_at=datetime(2019, 1, 1, tzinfo=timezone.utc),
        module=SimpleNamespace(key="logs"),
        role=SimpleNamespace(name="ops"),
        module_id=1,
        role_id=2,
    )
    line = _excess_perm_alert_line(old, cutoff)
    assert line is not None
    assert "ops" in line
    assert "logs" in line

    fresh = SimpleNamespace(
        can_write=True,
        can_delete=False,
        updated_at=datetime.now(timezone.utc),
        module=None,
        role=None,
        module_id=9,
        role_id=8,
    )
    assert _excess_perm_alert_line(fresh, cutoff) is None
    assert (
        _excess_perm_alert_line(
            SimpleNamespace(can_write=False, can_delete=False), cutoff
        )
        is None
    )


def test_validate_new_bastion_account_inputs_errors():
    realm = SimpleNamespace(
        provisioning_enabled=False,
        provisioning_service_account_id=None,
    )
    with pytest.raises(AccountCreationError, match="Identifiant"):
        _validate_new_bastion_account_inputs(
            realm=realm,
            username="",
            email="a@example.com",
            first_name="A",
            last_name="B",
            organization="Acme",
        )
    with pytest.raises(AccountCreationError, match="Prénom"):
        _validate_new_bastion_account_inputs(
            realm=realm,
            username="alice",
            email="a@example.com",
            first_name="",
            last_name="B",
            organization="Acme",
        )
    with pytest.raises(AccountCreationError, match="Email invalide"):
        _validate_new_bastion_account_inputs(
            realm=realm,
            username="alice",
            email="not-an-email",
            first_name="A",
            last_name="B",
            organization="Acme",
        )


def test_validate_new_bastion_account_inputs_ok(monkeypatch):
    realm = MagicMock()
    monkeypatch.setattr(
        "app.rbac.account_service.realm_provisioning_ready", lambda _r: True
    )
    monkeypatch.setattr(
        "app.rbac.account_service.normalize_organization_name",
        lambda v: (v or "").strip(),
    )
    out = _validate_new_bastion_account_inputs(
        realm=realm,
        username=" alice ",
        email=" a@example.com ",
        first_name=" Ann ",
        last_name=" Lee ",
        organization=" Acme ",
    )
    assert out == ("alice", "a@example.com", "Ann", "Lee", "Acme")


def test_apply_verify_outcome_branches():
    from app.web.session_verify import _INVALID_STREAK_TO_REVOKE, _apply_verify_outcome

    now = datetime.now(timezone.utc)
    revoke = MagicMock()

    active = SimpleNamespace(
        id=1, details={}, last_verified_status=None, last_verified_at=None
    )
    revoked, payload = _apply_verify_outcome(
        MagicMock(),
        active,
        status="active",
        now=now,
        actor="admin@example.com",
        email="user@example.com",
        ip_address="10.0.0.1",
        revoke_active_session=revoke,
    )
    assert revoked is False
    assert payload["last_verified_status"] == "active"
    assert active.details["consecutive_invalid_count"] == 0
    revoke.assert_not_called()

    soft = SimpleNamespace(
        id=2,
        details={"consecutive_invalid_count": 0},
        last_verified_status=None,
        last_verified_at=None,
    )
    revoked, payload = _apply_verify_outcome(
        MagicMock(),
        soft,
        status="invalid",
        now=now,
        actor=None,
        email="user@example.com",
        ip_address=None,
        revoke_active_session=revoke,
    )
    assert revoked is False
    assert payload["consecutive_invalid_count"] == 1
    revoke.assert_not_called()

    hard = SimpleNamespace(
        id=3,
        details={"consecutive_invalid_count": _INVALID_STREAK_TO_REVOKE - 1},
        last_verified_status=None,
        last_verified_at=None,
    )
    revoked, payload = _apply_verify_outcome(
        MagicMock(),
        hard,
        status="invalid",
        now=now,
        actor=None,
        email="user@example.com",
        ip_address="10.0.0.2",
        revoke_active_session=revoke,
    )
    assert revoked is True
    assert payload["revoked"] is True
    revoke.assert_called_once()

    unknown = SimpleNamespace(
        id=4,
        details={"consecutive_invalid_count": 5},
        last_verified_status=None,
        last_verified_at=None,
    )
    revoked, payload = _apply_verify_outcome(
        MagicMock(),
        unknown,
        status="unknown",
        now=now,
        actor="a",
        email="user@example.com",
        ip_address=None,
        revoke_active_session=revoke,
    )
    assert revoked is False
    assert payload["last_verified_status"] == "unknown"
    assert payload["consecutive_invalid_count"] == 5


@pytest.mark.asyncio
async def test_access_log_follow_once_paths(tmp_path: Path, monkeypatch):
    from app.web.nginx_app_logs import _access_log_follow_once

    settings = SimpleNamespace()
    missing = tmp_path / "missing.log"
    chunk, offset, stop = await _access_log_follow_once(
        missing, settings, "app1", lines=10, offset=0
    )
    assert chunk is None
    assert offset == 0
    assert stop is False

    log = tmp_path / "access.log"
    log.write_bytes(b"line1\nline2\n")
    size = log.stat().st_size
    chunk, offset, stop = await _access_log_follow_once(
        log, settings, "app1", lines=10, offset=size
    )
    assert chunk is None
    assert offset == size
    assert stop is False

    log.write_bytes(b"line1\nline2\nline3\n")
    chunk, offset, stop = await _access_log_follow_once(
        log, settings, "app1", lines=10, offset=size
    )
    assert chunk is not None
    assert "line3" in chunk
    assert stop is False

    monkeypatch.setattr(
        "app.web.nginx_app_logs.read_access_log_tail",
        lambda *_a, **_k: "rotated\n",
    )
    chunk, offset, stop = await _access_log_follow_once(
        log, settings, "app1", lines=10, offset=10_000
    )
    assert chunk == "rotated\n"
    assert stop is False


def test_redirect_apply_terminal_and_timeout(monkeypatch):
    from app.web.admin_infrastructure import (
        _redirect_apply_terminal,
        _redirect_apply_timeout,
    )

    flashes: list[tuple] = []

    monkeypatch.setattr(
        "app.web.admin_infrastructure.flash_redirect",
        lambda resp, msg, level, token: flashes.append((msg, level)),
    )
    monkeypatch.setattr(
        "app.web.admin_infrastructure.log_action",
        lambda *a, **k: None,
    )

    user = SimpleNamespace(email="admin@example.com")
    state = {
        "status_path": "/tmp/st",
        "log_path": "/tmp/log",
        "request_pending": False,
    }

    ok = _redirect_apply_terminal(
        db=MagicMock(),
        user=user,
        status="ok",
        state=state,
        next_path="/admin/infrastructure",
        context_label="Export OK",
        target="infrastructure",
        source="admin.infrastructure",
        elapsed=3,
        token="dev",
    )
    assert ok.status_code == 302
    assert flashes[-1][1] == "success"

    fail = _redirect_apply_terminal(
        db=MagicMock(),
        user=user,
        status="error",
        state=state,
        next_path="/admin/infrastructure",
        context_label="",
        target="infrastructure",
        source="admin.infrastructure",
        elapsed=3,
        token="dev",
    )
    assert fail.status_code == 302
    assert flashes[-1][1] == "error"

    timed = _redirect_apply_timeout(
        db=MagicMock(),
        user=user,
        state=state,
        context_label="Ctx",
        target="infrastructure",
        source="admin.infrastructure",
        elapsed=99,
        timeout=60,
        token="dev",
    )
    assert timed.status_code == 302
    assert "60s" in flashes[-1][0]


def test_group_delete_fail_response_json_and_redirect(monkeypatch):
    from starlette.requests import Request as StarletteRequest

    from app.admin.rbac_groups import _group_delete_fail_response

    flashes: list[str] = []
    monkeypatch.setattr(
        "app.admin.rbac_groups.flash_redirect",
        lambda resp, msg, level, secret: flashes.append(msg),
    )

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "path": "/admin/rbac/groups/1/delete",
        "raw_path": b"/admin/rbac/groups/1/delete",
        "root_path": "",
        "scheme": "https",
        "query_string": b"",
        "headers": [(b"accept", b"application/json")],
        "client": ("10.0.0.1", 1234),
        "server": ("portal.example.com", 443),
    }
    req = StarletteRequest(scope)
    json_resp = _group_delete_fail_response(
        req,
        redirect_url=None,
        group_id=1,
        msg="busy",
        status_code=409,
        secret="dev",
    )
    assert json_resp.status_code == 409

    scope2 = dict(scope)
    scope2["headers"] = [(b"accept", b"text/html")]
    req2 = StarletteRequest(scope2)
    html = _group_delete_fail_response(
        req2,
        redirect_url="/admin/rbac",
        group_id=1,
        msg="busy",
        status_code=409,
        secret="dev",
    )
    assert html.status_code == 302
    assert flashes[-1] == "busy"


def test_fetch_live_audit_entries_filters(monkeypatch):
    from app.web import admin_logs as mod

    rows = [SimpleNamespace(id=10)]
    qset = MagicMock()
    qset.order_by.return_value.limit.return_value.all.return_value = rows
    db = MagicMock()
    db.query.return_value.filter.return_value = qset

    class _Ctx:
        def __enter__(self):
            return db

        def __exit__(self, *a):
            return False

    # SessionLocal() used as factory returning an object with close()
    session = MagicMock()
    session.query.return_value.filter.return_value = qset
    monkeypatch.setattr(mod, "SessionLocal", lambda: session)
    monkeypatch.setattr(
        mod,
        "apply_audit_filters",
        lambda qs, **_k: qs,
    )
    monkeypatch.setattr(
        mod,
        "serialize_audit_row",
        lambda r, locale=None: {"id": r.id, "action": "login"},
    )

    def _match(entry, **kwargs):
        return entry["id"] == 10

    out = mod._fetch_live_audit_entries(
        last_id=1,
        locale="fr",
        filters={
            "action": "login",
            "actor": None,
            "df": None,
            "dt": None,
            "ip": None,
            "q": None,
            "detail": None,
            "event_code": None,
            "statuses": None,
            "domains": None,
            "severities": None,
            "sev_min": None,
        },
        entry_matches_live_filters=_match,
    )
    assert out == [{"id": 10, "action": "login"}]
    session.close.assert_called_once()


def test_reset_password_error_response_paths(monkeypatch):
    from starlette.requests import Request as StarletteRequest

    from app.admin.rbac_accounts import _reset_password_error_response

    flashes: list[str] = []
    monkeypatch.setattr(
        "app.admin.rbac_accounts.flash_redirect",
        lambda resp, msg, level, secret: flashes.append(msg),
    )

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "path": "/admin/rbac/accounts/1/reset-password",
        "raw_path": b"/x",
        "root_path": "",
        "scheme": "https",
        "query_string": b"",
        "headers": [(b"accept", b"application/json")],
        "client": ("10.0.0.1", 1234),
        "server": ("portal.example.com", 443),
    }
    json_resp = _reset_password_error_response(
        StarletteRequest(scope),
        exc=RuntimeError("boom"),
        redirect_url="",
        fallback="/admin/rbac",
        secret="dev",
    )
    assert json_resp.status_code == 400

    scope2 = dict(scope)
    scope2["headers"] = [(b"accept", b"text/html")]
    html = _reset_password_error_response(
        StarletteRequest(scope2),
        exc=RuntimeError("boom"),
        redirect_url="/admin/rbac/accounts/1",
        fallback="/admin/rbac",
        secret="dev",
    )
    assert html.status_code == 302
    assert flashes[-1] == "boom"
