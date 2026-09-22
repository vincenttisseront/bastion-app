"""Coverage for oauth2-auth helpers extracted for Sonar S3776."""

from __future__ import annotations

from unittest.mock import MagicMock

from starlette.responses import Response

from app.auth import _apply_oauth2_sso_binding, _breakglass_auth_response


def test_apply_oauth2_sso_binding_commits(monkeypatch):
    db = MagicMock()
    request = MagicMock()
    resp = Response(status_code=200)
    resp.headers["X-Auth-Request-Email"] = "user@example.com"
    resp.headers["X-Auth-Request-Preferred-Username"] = "user"
    resp.headers["X-Auth-Request-User"] = "user"

    called = {}

    def eval_binding(*_a, **_k):
        called["ok"] = True

    monkeypatch.setattr("app.auth.evaluate_sso_binding", eval_binding)
    _apply_oauth2_sso_binding(db, request, resp)
    assert called.get("ok") is True
    db.commit.assert_called_once()


def test_apply_oauth2_sso_binding_rolls_back_on_error(monkeypatch):
    db = MagicMock()
    request = MagicMock()
    resp = Response(status_code=200)

    def boom(*_a, **_k):
        raise RuntimeError("fail")

    monkeypatch.setattr("app.auth.evaluate_sso_binding", boom)
    _apply_oauth2_sso_binding(db, request, resp)
    db.rollback.assert_called_once()


def test_breakglass_auth_response_ok_and_denied(monkeypatch):
    db = MagicMock()
    request = MagicMock()
    settings = MagicMock()

    monkeypatch.setattr(
        "app.auth.process_breakglass_auth_request",
        lambda *_a, **_k: MagicMock(ok=True),
    )
    ok = _breakglass_auth_response(db, request, settings, "cookie")
    assert ok is not None
    assert ok.status_code == 200
    assert ok.headers.get("X-Auth-Source") == "breakglass"

    monkeypatch.setattr(
        "app.auth.process_breakglass_auth_request",
        lambda *_a, **_k: MagicMock(ok=False),
    )
    denied = _breakglass_auth_response(db, request, settings, "cookie")
    assert denied is not None
    assert denied.status_code == 401
