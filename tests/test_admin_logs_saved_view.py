"""Coverage for admin logs saved-view filter merge helpers."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.models import SavedLogView
from app.web.admin_logs import _apply_saved_view_defaults, _merge_saved_view_filters


def test_merge_saved_view_filters_no_view_passthrough():
    out = _merge_saved_view_filters(
        MagicMock(),
        "admin@example.com",
        None,
        action="a",
        actor="b",
        date_from=None,
        date_to=None,
        ip=None,
        q=None,
        detail=None,
        status=None,
        domain=None,
        severity=None,
        severity_min=None,
        event_code=None,
        columns=None,
    )
    assert out[0] == "a"
    assert out[1] == "b"
    assert out[12] is None


def test_apply_saved_view_defaults_fills_missing():
    saved = MagicMock(spec=SavedLogView)
    saved.id = 7
    saved.filters_json = {
        "action": "login",
        "actor": "ops",
        "status": ["ok"],
        "domain": ["auth"],
        "severity": ["HIGH"],
        "severity_min": "MEDIUM",
        "event_code": "E1",
        "q": "needle",
    }
    saved.columns_json = ["action", "actor"]
    out = _apply_saved_view_defaults(
        saved,
        {
            "action": None,
            "actor": None,
            "date_from": None,
            "date_to": None,
            "ip": None,
            "q": None,
            "detail": None,
            "status": None,
            "domain": None,
            "severity": None,
            "severity_min": None,
            "event_code": None,
            "columns": None,
        },
    )
    assert out[0] == "login"
    assert out[1] == "ops"
    assert out[5] == "needle"
    assert out[7] == ["ok"]
    assert out[8] == ["auth"]
    assert out[9] == ["HIGH"]
    assert out[10] == "MEDIUM"
    assert out[11] == "E1"
    assert out[12] == 7
    assert out[13] == "action,actor"
