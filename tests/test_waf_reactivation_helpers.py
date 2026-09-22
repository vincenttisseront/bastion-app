"""Coverage for WAF reactivation helpers and subdomain preflight."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.bastion.waf_reactivation import (
    _probe_one_subdomain_host,
    _reactivate_smoke_failure,
    _reactivate_subdomain_preflight,
    _reactivate_wait_for_engine,
)


def test_reactivate_wait_injected_short_circuits():
    assert (
        _reactivate_wait_for_engine(
            MagicMock(),
            MagicMock(),
            profile=MagicMock(),
            previous_mode="Off",
            prev_arm={},
            actor="admin",
            paths={},
            sync_detail="ok",
            sync_fn=lambda _s: (True, "ok"),
            injected=True,
        )
        is None
    )


def test_reactivate_wait_rolls_back_when_engine_not_ready(monkeypatch):
    monkeypatch.setattr(
        "app.bastion.waf_reactivation.wait_for_nginx_edge",
        lambda _s: {"ok": True},
    )
    monkeypatch.setattr(
        "app.bastion.waf_reactivation.wait_for_portal_engine_mode",
        lambda *_a, **_k: {"ok": False, "mode": "Off"},
    )
    rolled = {"n": 0}

    def fake_rollback(*_a, **_k):
        rolled["n"] += 1

    monkeypatch.setattr("app.bastion.waf_reactivation._rollback", fake_rollback)
    out = _reactivate_wait_for_engine(
        MagicMock(),
        MagicMock(),
        profile=MagicMock(),
        previous_mode="Off",
        prev_arm={},
        actor="admin",
        paths={"x": "y"},
        sync_detail="synced",
        sync_fn=lambda _s: (True, "ok"),
        injected=False,
    )
    assert out is not None
    assert out["ok"] is False
    assert out["rolled_back"] is True
    assert rolled["n"] == 1


def test_reactivate_smoke_failure_payload(monkeypatch):
    monkeypatch.setattr("app.bastion.waf_reactivation._rollback", lambda *_a, **_k: None)
    out = _reactivate_smoke_failure(
        MagicMock(),
        MagicMock(),
        profile=MagicMock(),
        previous_mode="Off",
        prev_arm={},
        actor="admin",
        paths={},
        sync_detail="ok",
        sync_fn=lambda _s: (True, "ok"),
        smoke_result={
            "ok": False,
            "failed": [{"url": "/auth/login", "status": 500}],
            "failed_summary": "boom",
        },
    )
    assert out["ok"] is False
    assert "Smoke" in out["error"]
    assert out["failed_summary"] == "boom"


def test_probe_one_subdomain_host_success(monkeypatch):
    monkeypatch.setattr(
        "app.bastion.waf_reactivation._http_probe",
        lambda *_a, **_k: {"ok": True, "status": 302},
    )
    probe = _probe_one_subdomain_host(
        "app.example.com", base="http://nginx:8080", paths=("/auth/login",)
    )
    assert probe["ok"] is True
    assert probe["subdomain_host"] == "app.example.com"


def test_subdomain_preflight_requires_confirm_and_portal_armed(monkeypatch):
    settings = MagicMock()
    err = _reactivate_subdomain_preflight(MagicMock(), settings, confirm=False)
    assert isinstance(err, dict)
    assert err["ok"] is False

    monkeypatch.setattr(
        "app.bastion.waf_reactivation.read_arm_state", lambda _s: {"armed": False}
    )
    err2 = _reactivate_subdomain_preflight(MagicMock(), settings, confirm=True)
    assert isinstance(err2, dict)
    assert "portal" in err2["error"].lower() or "armé" in err2["error"].lower()


def test_subdomain_wait_and_smoke_helpers(monkeypatch):
    from app.bastion.waf_reactivation import (
        _reactivate_subdomain_smoke_failure,
        _reactivate_subdomain_wait_for_engine,
    )

    assert (
        _reactivate_subdomain_wait_for_engine(
            MagicMock(),
            prev_arm={},
            actor="a",
            paths={},
            sync_detail="ok",
            sync_fn=lambda _s: (True, "ok"),
            injected=True,
        )
        is None
    )

    monkeypatch.setattr(
        "app.bastion.waf_reactivation.wait_for_nginx_edge",
        lambda _s: {"ok": True},
    )
    monkeypatch.setattr(
        "app.bastion.waf_reactivation.wait_for_subdomain_engine_mode",
        lambda *_a, **_k: {"ok": False, "mode": "Off", "export_mode": "Off"},
    )
    monkeypatch.setattr(
        "app.bastion.waf_reactivation._rollback_subdomain", lambda *_a, **_k: None
    )
    fail = _reactivate_subdomain_wait_for_engine(
        MagicMock(),
        prev_arm={},
        actor="a",
        paths={"p": "1"},
        sync_detail="synced",
        sync_fn=lambda _s: (True, "ok"),
        injected=False,
    )
    assert fail is not None
    assert fail["rolled_back"] is True

    smoke_fail = _reactivate_subdomain_smoke_failure(
        MagicMock(),
        prev_arm={},
        actor="a",
        paths={},
        sync_detail="ok",
        sync_fn=lambda _s: (True, "ok"),
        smoke_result={"ok": False, "failed_summary": "bad", "failed": []},
    )
    assert smoke_fail["ok"] is False
    assert "Smoke" in smoke_fail["error"]
