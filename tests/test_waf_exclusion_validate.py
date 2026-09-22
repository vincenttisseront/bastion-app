"""Coverage for WAF exclusion field validation (S3776 helper split)."""

from __future__ import annotations

import pytest

from app.bastion.nginx_waf_export import SCOPE_ARGS, SCOPE_RULE
from app.security.waf.service import _validate_exclusion_fields


def test_validate_exclusion_ok_scoped():
    reason, uri, host, kind, target, match = _validate_exclusion_fields(
        reason=" FP ",
        crs_rule_id=942100,
        uri_pattern="/login",
        host="App.Example.com",
        scope_kind=SCOPE_RULE,
        target_name=None,
        uri_match="exact",
        allow_global=False,
    )
    assert reason == "FP"
    assert uri == "/login"
    assert host == "app.example.com"
    assert kind == SCOPE_RULE
    assert match == "exact"
    assert target is None


def test_validate_exclusion_rejects_missing_reason_and_rule():
    with pytest.raises(ValueError, match="raison"):
        _validate_exclusion_fields(
            reason="  ",
            crs_rule_id=1,
            uri_pattern="/x",
            host=None,
            scope_kind=None,
            target_name=None,
            uri_match=None,
            allow_global=False,
        )
    with pytest.raises(ValueError, match="crs_rule_id"):
        _validate_exclusion_fields(
            reason="ok",
            crs_rule_id=None,
            uri_pattern="/x",
            host=None,
            scope_kind=None,
            target_name=None,
            uri_match=None,
            allow_global=False,
        )


def test_validate_exclusion_global_and_args_require_target():
    with pytest.raises(ValueError, match="host ou URI"):
        _validate_exclusion_fields(
            reason="ok",
            crs_rule_id=1,
            uri_pattern=None,
            host=None,
            scope_kind=SCOPE_RULE,
            target_name=None,
            uri_match=None,
            allow_global=False,
        )
    ok = _validate_exclusion_fields(
        reason="ok",
        crs_rule_id=1,
        uri_pattern=None,
        host=None,
        scope_kind=SCOPE_RULE,
        target_name=None,
        uri_match=None,
        allow_global=True,
    )
    assert ok[0] == "ok"
    with pytest.raises(ValueError, match="nom de variable"):
        _validate_exclusion_fields(
            reason="ok",
            crs_rule_id=1,
            uri_pattern="/x",
            host=None,
            scope_kind=SCOPE_ARGS,
            target_name=None,
            uri_match=None,
            allow_global=False,
        )


def test_validate_exclusion_invalid_kind_and_match():
    with pytest.raises(ValueError, match="scope_kind"):
        _validate_exclusion_fields(
            reason="ok",
            crs_rule_id=1,
            uri_pattern="/x",
            host=None,
            scope_kind="nope",
            target_name=None,
            uri_match=None,
            allow_global=False,
        )
    with pytest.raises(ValueError, match="uri_match"):
        _validate_exclusion_fields(
            reason="ok",
            crs_rule_id=1,
            uri_pattern="/x",
            host=None,
            scope_kind=SCOPE_RULE,
            target_name=None,
            uri_match="weird",
            allow_global=False,
        )
