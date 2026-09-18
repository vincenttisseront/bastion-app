"""Unit coverage for flash template branding resolution helper."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.web.flash import _resolve_branding_for_template


def test_resolve_branding_prefers_explicit_extra():
    branding = {"company_name": "Example"}
    out = _resolve_branding_for_template({"branding": branding}, db=None)
    assert out is branding


def test_resolve_branding_uses_request_db():
    db = MagicMock()
    with patch("app.branding.get_branding_settings", return_value={"ok": True}) as get:
        out = _resolve_branding_for_template({}, db)
    get.assert_called_once_with(db)
    assert out == {"ok": True}


def test_resolve_branding_opens_temp_session_when_no_db():
    with (
        patch("app.database.SessionLocal") as SessionLocal,
        patch("app.branding.get_branding_settings", return_value={"tmp": 1}) as get,
    ):
        tmp = MagicMock()
        SessionLocal.return_value = tmp
        out = _resolve_branding_for_template({}, db=None)
    get.assert_called_once_with(tmp)
    tmp.close.assert_called_once()
    assert out == {"tmp": 1}
