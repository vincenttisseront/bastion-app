"""Unit coverage for S3776 helpers extracted in batch8."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.bastion.login_form_analyzer import analyze_html
from app.bastion.nginx_waf_export import (
    _drop_dangling_chain_secrules,
    _drop_unsafe_secrule_lines,
    _sanitize_generated_rules,
)
from app.db.hot_store_service import HotStoreError, _normalize_hot_store_fields
from app.oidc_bff import _oidc_row_matches_identity
from app.portal_settings_service import _normalize_smtp_fields


def test_normalize_smtp_fields_ok_and_errors():
    fields = _normalize_smtp_fields(
        smtp_enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=465,
        smtp_use_tls=True,
        smtp_username="ops",
        smtp_from_email="noreply@example.com",
        smtp_from_name="Bastion",
        daily_recap_enabled=True,
        daily_recap_email="ops@example.com",
        daily_recap_hour=8,
    )
    assert fields["host"] == "smtp.example.com"
    assert fields["port"] == 465
    assert fields["recap_hour"] == 8

    with pytest.raises(ValueError, match="Hôte SMTP"):
        _normalize_smtp_fields(
            smtp_enabled=True,
            smtp_host="",
            smtp_port=587,
            smtp_use_tls=True,
            smtp_username=None,
            smtp_from_email="a@example.com",
            smtp_from_name=None,
            daily_recap_enabled=False,
            daily_recap_email=None,
            daily_recap_hour=7,
        )
    with pytest.raises(ValueError, match="invalide"):
        _normalize_smtp_fields(
            smtp_enabled=False,
            smtp_host=None,
            smtp_port=None,
            smtp_use_tls=False,
            smtp_username=None,
            smtp_from_email=None,
            smtp_from_name=None,
            daily_recap_enabled=True,
            daily_recap_email="not-an-email",
            daily_recap_hour=7,
        )


def test_normalize_hot_store_fields():
    out = _normalize_hot_store_fields(
        host=" pg.example.com ",
        port=5432,
        database="",
        user="",
        sslmode="prefer",
    )
    assert out["host"] == "pg.example.com"
    assert out["database"] == "bastion_hot"
    assert out["user"] == "bastion_hot"
    with pytest.raises(HotStoreError, match="sslmode"):
        _normalize_hot_store_fields(
            host="pg.example.com",
            port=5432,
            database="db",
            user="u",
            sslmode="weird",
        )
    with pytest.raises(HotStoreError, match="Hôte"):
        _normalize_hot_store_fields(
            host="  ",
            port=5432,
            database="db",
            user="u",
            sslmode="prefer",
        )


def test_sanitize_generated_rules_helpers():
    raw = "\n".join(
        [
            "SecRule ARGS \"@rx %\" \"id:1\"",
            "SecRule ARGS \"@rx x\" \"id:2,nolog,chain\"",
            "# comment",
            "SecRule ARGS \"@rx y\" \"id:3\"",
        ]
    )
    cleaned = _drop_unsafe_secrule_lines(raw.splitlines())
    assert any("skipped unsafe" in line for line in cleaned)
    dangling = _drop_dangling_chain_secrules(
        ["SecRule ARGS \"@rx x\" \"id:2,nolog,chain\"", "# only"]
    )
    assert any("dangling chain" in line for line in dangling)
    out = _sanitize_generated_rules(raw)
    assert out.endswith("\n")


def test_analyze_html_password_form():
    html = """
    <html><body>
      <form action="/login" method="post">
        <input type="text" name="user">
        <input type="password" name="pass">
        <input type="hidden" name="csrf" value="tok">
      </form>
      <form action="/search"><input name="q"></form>
    </body></html>
    """
    forms = analyze_html(html, "https://app.example.com/")
    assert len(forms) == 1
    assert forms[0]["password_field"]["name"] == "pass"
    assert forms[0]["method"] == "POST"
    assert forms[0]["field_count"] >= 2


def test_oidc_row_matches_identity():
    row = SimpleNamespace(username="Alice", sub="kc-1")
    assert _oidc_row_matches_identity(
        row, emails=set(), usernames={"alice"}, subs=set()
    )
    assert _oidc_row_matches_identity(
        row, emails={"alice"}, usernames=set(), subs=set()
    )
    assert _oidc_row_matches_identity(
        row, emails=set(), usernames=set(), subs={"kc-1"}
    )
    assert not _oidc_row_matches_identity(
        row, emails={"other@example.com"}, usernames={"bob"}, subs={"x"}
    )


def test_seed_breakglass_first_sight():
    from app.security.session_binding_service import _seed_breakglass_first_sight

    db = MagicMock()
    row = SimpleNamespace(
        first_ip_subnet=None,
        first_fingerprint_hash=None,
        last_ip_subnet=None,
        last_fingerprint_hash=None,
        mismatch_count=None,
    )
    _seed_breakglass_first_sight(db, row, subnet="10.0.0.0/24", fp="abc")
    assert row.first_ip_subnet == "10.0.0.0/24"
    assert row.first_fingerprint_hash == "abc"
    assert row.mismatch_count == 0
    db.flush.assert_called_once()
