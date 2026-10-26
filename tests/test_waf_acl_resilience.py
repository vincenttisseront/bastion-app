"""Resilience / stress tests for WAF + ACL export pipeline (v1.2 seal).

Adapted to FastAPI/SQLAlchemy Bastion APIs (not Django). Nginx reload timing is
soft when Docker is unavailable so CI stays non-flaky.
"""

from __future__ import annotations

import concurrent.futures
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy.orm import sessionmaker

from app.bastion.nginx_waf_export import (
    apply_waf_exports,
    list_promoted_deny_ips,
    render_ip_allow_conf,
    render_ip_deny_conf,
    write_waf_exports,
)
from app.models import SecurityBan, WafProfile
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}

DENYLIST_N = 10_000
CONCURRENCY_WRITERS = 50
SANDBOX_THREADS = 100


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        portal_domain="portal.example.com",
        exports_dir=str(tmp_path / "exports"),
        portal_data_dir=str(tmp_path / "data"),
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        breakglass_jwt_secret_fallback_enabled=True,
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )


def _seed_profile(db, *, min_occ: int = 1) -> WafProfile:
    profile = WafProfile(
        name="Resilience",
        mode="on",
        is_active=True,
        ip_deny_min_occurrences=min_occ,
        patch_php2shell_mode="on",
    )
    db.add(profile)
    db.commit()
    return profile


def _bulk_permanent_bans(db, n: int = DENYLIST_N) -> float:
    """Insert n distinct permanent IP bans; return wall time."""
    start = time.perf_counter()
    batch: list[SecurityBan] = []
    for i in range(n):
        # Unique IPs in TEST-NET-3 (documentation range).
        a, b = divmod(i, 256)
        c, d = divmod(a, 256)
        ip = f"203.{c % 256}.{d}.{b}"
        batch.append(
            SecurityBan(
                target_type="ip",
                target=ip,
                reason="resilience bulk load",
                rule_type="manual",
                permanent=True,
            )
        )
        if len(batch) >= 500:
            db.add_all(batch)
            db.commit()
            batch.clear()
    if batch:
        db.add_all(batch)
        db.commit()
    return time.perf_counter() - start


# -------------------------------------------------------------------------
# S1 — Denylist volumetry (10k)
# -------------------------------------------------------------------------
def test_resilience_denylist_10k_volumetry(db_session, tmp_path):
    settings = _settings(tmp_path)
    _seed_profile(db_session, min_occ=1)

    db_duration = _bulk_permanent_bans(db_session, DENYLIST_N)
    assert db_session.query(SecurityBan).count() >= DENYLIST_N

    start_export = time.perf_counter()
    paths = write_waf_exports(db_session, settings)
    export_duration = time.perf_counter() - start_export

    deny_path = Path(paths["waf-ip-deny.conf"])
    assert deny_path.is_file()
    text = deny_path.read_text(encoding="utf-8")
    deny_lines = [ln for ln in text.splitlines() if ln.startswith("deny ")]
    assert len(deny_lines) >= DENYLIST_N
    file_size_kb = deny_path.stat().st_size / 1024
    assert file_size_kb > 150

    promoted = list_promoted_deny_ips(db_session, min_occurrences=1)
    assert len(promoted) >= DENYLIST_N

    # Soft nginx path: validator may skip without Docker.
    start_reload = time.perf_counter()

    def _fake_validate(_settings):
        # Simulate a fast successful nginx -t when Docker is absent.
        time.sleep(0.01)
        return True, "nginx -t skipped (resilience unit)", True

    result = apply_waf_exports(db_session, settings, validate=_fake_validate)
    reload_duration = time.perf_counter() - start_reload
    assert result["ok"] is True

    print(
        f"\n[S1] DB bulk: {db_duration:.3f}s | export: {export_duration:.3f}s | "
        f"file: {file_size_kb:.1f} KiB | apply: {reload_duration*1000:.1f} ms"
    )
    if reload_duration > 0.5:
        print(
            f"  WARNING: apply path took {reload_duration*1000:.1f}ms (>500ms soft limit)"
        )


# -------------------------------------------------------------------------
# S2 — Concurrent apply / atomic writes
# -------------------------------------------------------------------------
def test_resilience_concurrency_stress_apply(db_engine, tmp_path):
    settings = _settings(tmp_path)
    SessionLocal = sessionmaker(bind=db_engine)
    with SessionLocal() as db:
        _seed_profile(db, min_occ=1)
        db.add(
            SecurityBan(
                target_type="ip",
                target="203.0.113.77",
                reason="seed",
                permanent=True,
                rule_type="manual",
            )
        )
        db.commit()

    # Warm a first export so .prev backups exist.
    with SessionLocal() as db:
        write_waf_exports(db, settings)

    def worker(_wid: int) -> tuple[bool, str, list[str]]:
        try:
            with SessionLocal() as db:
                paths = write_waf_exports(db, settings)
            for name, path in paths.items():
                p = Path(path)
                assert p.is_file(), name
                assert p.stat().st_size > 0, f"truncated {name}"
            deny = Path(settings.exports_dir) / "waf-ip-deny.conf"
            body = deny.read_text(encoding="utf-8")
            assert "deny 203.0.113.77;" in body
            return True, "ok", list(paths.values())
        except Exception as exc:  # noqa: BLE001 — collect for assertion
            return False, str(exc), []

    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY_WRITERS) as pool:
        futures = [pool.submit(worker, i) for i in range(CONCURRENCY_WRITERS)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    failures = [msg for ok, msg, _ in results if not ok]
    assert not failures, f"concurrent write failures: {failures[:3]}"


# -------------------------------------------------------------------------
# S3 — Empty ACL files + rollback on bad conf
# -------------------------------------------------------------------------
def test_resilience_empty_configs_and_rollback(db_session, tmp_path):
    from app.bastion.nginx_waf_export import restore_waf_exports_previous

    settings = _settings(tmp_path)
    _seed_profile(db_session, min_occ=1)

    # Empty allow/deny still render valid include stubs (comments may mention allow/deny).
    allow_text = render_ip_allow_conf([])
    deny_text = render_ip_deny_conf([], min_occurrences=1)
    live_allow = [ln for ln in allow_text.splitlines() if ln.strip().startswith("allow ")]
    live_deny = [ln for ln in deny_text.splitlines() if ln.strip().startswith("deny ")]
    assert live_allow == []
    assert live_deny == []

    paths = write_waf_exports(db_session, settings)
    deny_path = Path(paths["waf-ip-deny.conf"])
    allow_path = Path(paths["waf-ip-allow.conf"])
    assert deny_path.is_file() and allow_path.is_file()
    good_body = deny_path.read_text(encoding="utf-8")

    # Second write creates *.prev snapshots; then corrupt live deny and restore.
    write_waf_exports(db_session, settings)
    deny_path.write_text(
        good_body + "\nINVALIDE_DIRECTIVE broken;\n", encoding="utf-8"
    )
    assert "INVALIDE_DIRECTIVE" in deny_path.read_text(encoding="utf-8")

    restored = restore_waf_exports_previous(settings)
    assert any("waf-ip-deny" in r for r in restored)
    assert "INVALIDE_DIRECTIVE" not in deny_path.read_text(encoding="utf-8")

    # apply_waf_exports: write succeeds then validate fails → restore *.prev.
    def _fail_validate(_settings):
        return False, "unknown directive INVALIDE_DIRECTIVE", False

    result = apply_waf_exports(db_session, settings, validate=_fail_validate)
    assert result["ok"] is False
    assert result.get("restored")
    assert Path(paths["waf-ip-deny.conf"]).stat().st_size > 0


# -------------------------------------------------------------------------
# S4 — Sandbox high concurrency (timeout + isolation)
# -------------------------------------------------------------------------
def test_resilience_sandbox_high_concurrency_load(client, monkeypatch, tmp_path):
    """Starlette TestClient is not thread-safe — stress the helper concurrently,
    then smoke the HTTP endpoint sequentially."""
    from app.bastion.waf_sandbox import run_waf_sandbox

    settings = _settings(tmp_path)
    seen_ids: list[str] = []
    lock = __import__("threading").Lock()
    counter = {"n": 0}

    def fake_open(req, timeout=0):  # noqa: ARG001
        class _Resp:
            status = 204

            def read(self, _n=0):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return _Resp()

    monkeypatch.setattr(
        "app.bastion.waf_sandbox.read_nginx_waf_reality",
        lambda **kw: {"verifiable": False},
    )
    monkeypatch.setattr(
        "app.bastion.waf_sandbox.read_arm_state",
        lambda _s: {"armed": True},
    )
    monkeypatch.setattr(
        "app.bastion.waf_sandbox.build_sandbox_readiness",
        lambda *a, **k: {"warnings": [], "usable": True},
    )
    monkeypatch.setattr(
        "app.bastion.waf_sandbox.resolve_modsec_audit_log_path",
        lambda _s: tmp_path / "missing-modsec_audit.log",
    )
    monkeypatch.setattr("app.bastion.waf_sandbox.AUDIT_WAIT_SEC", 0.05)
    from app.bastion import waf_sandbox as sb

    monkeypatch.setattr(sb._PROBE_OPENER, "open", fake_open)

    def worker(i: int) -> tuple[str, float]:
        start = time.perf_counter()
        result = run_waf_sandbox(
            settings,
            method="POST",
            uri="/login",
            body=f'{{"q":"UNION SELECT {i}"}}',
            content_type="application/json",
        )
        with lock:
            seen_ids.append(result["sandbox_id"])
            counter["n"] += 1
        return result["sandbox_id"], time.perf_counter() - start

    with concurrent.futures.ThreadPoolExecutor(max_workers=SANDBOX_THREADS) as pool:
        futures = [pool.submit(worker, i) for i in range(SANDBOX_THREADS)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    for sid, duration in results:
        assert sid
        assert duration < 2.5, f"sandbox exceeded soft timeout: {duration:.3f}s"
    assert counter["n"] == SANDBOX_THREADS
    assert len(set(seen_ids)) == SANDBOX_THREADS

    # HTTP endpoint wiring (sequential — TestClient is not multi-threaded).
    with patch(
        "app.bastion.waf_sandbox.run_waf_sandbox",
        return_value={
            "sandbox_id": "http-smoke",
            "method": "POST",
            "uri": "/login",
            "blocked_intent": False,
            "matched_rules": [],
            "verdict": "clean",
            "probe": {"ok": True, "status": 204},
            "audit_found": True,
            "readiness": {"warnings": []},
        },
    ):
        resp = client.post(
            "/admin/security/waf/sandbox",
            headers=ADMIN_HEADERS,
            data={
                "method": "POST",
                "uri": "/login",
                "content_type": "application/json",
                "body": '{"q":"1"}',
            },
        )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
