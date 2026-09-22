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
    assert "ops" in line and "logs" in line

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
