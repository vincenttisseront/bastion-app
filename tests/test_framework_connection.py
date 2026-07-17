"""Unit tests for the shared connection-test framework."""

from __future__ import annotations

import json
import time

from app.testing_framework.connection_test import (
    CheckStatus,
    CheckStep,
    ConnectionTestResult,
    overall_from_checks,
)
from app.testing_framework.throttle import check_throttle, reset_throttles


def test_overall_from_checks_ok_only():
    checks = [
        CheckStep("a", CheckStatus.OK, "ok"),
        CheckStep("b", CheckStatus.OK, "ok"),
    ]
    assert overall_from_checks(checks) == CheckStatus.OK


def test_overall_from_checks_warn_wins_over_ok():
    checks = [
        CheckStep("a", CheckStatus.OK, "ok"),
        CheckStep("b", CheckStatus.WARN, "warn"),
    ]
    assert overall_from_checks(checks) == CheckStatus.WARN


def test_overall_from_checks_error_wins():
    checks = [
        CheckStep("a", CheckStatus.OK, "ok"),
        CheckStep("b", CheckStatus.WARN, "warn"),
        CheckStep("c", CheckStatus.ERROR, "err"),
    ]
    assert overall_from_checks(checks) == CheckStatus.ERROR


def test_check_throttle_same_resource():
    reset_throttles()
    assert check_throttle("oidc_realm", 1, min_interval_seconds=5) is True
    assert check_throttle("oidc_realm", 1, min_interval_seconds=5) is False


def test_check_throttle_different_resources():
    reset_throttles()
    assert check_throttle("oidc_realm", 1) is True
    assert check_throttle("oidc_realm", 2) is True
    assert check_throttle("app_health", 1) is True


def test_check_throttle_after_delay():
    reset_throttles()
    assert check_throttle("app_credential", "transfer", min_interval_seconds=1) is True
    assert check_throttle("app_credential", "transfer", min_interval_seconds=1) is False
    time.sleep(1.05)
    assert check_throttle("app_credential", "transfer", min_interval_seconds=1) is True


def test_to_api_dict_never_contains_sensitive_keywords_in_serialized_detail():
    result = ConnectionTestResult(
        resource_type="oidc_realm",
        resource_id="demo",
        overall_status=CheckStatus.OK,
        checks=[
            CheckStep(
                name="client_credentials",
                status=CheckStatus.OK,
                message="Client credentials valides",
                detail={"client_secret": "LEAK", "password": "LEAK", "token": "LEAK"},
            )
        ],
        latency_ms=12,
    )
    payload = result.to_api_dict()
    serialized = json.dumps(payload)
    assert "detail" not in payload["checks"][0]
    assert "LEAK" not in serialized
    assert "client_secret" not in serialized
    assert '"password"' not in serialized
