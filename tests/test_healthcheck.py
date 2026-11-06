"""Self-healing container healthcheck (app/healthcheck.py) — no Docker needed."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from app import healthcheck
from app.ip_cidrs import LOOPBACK_V4_HOST

FAKE_SIGUSR1 = 10
FAKE_SIGKILL = 9


def _proc(root: Path, pid: int, ppid: int, cmdline: bytes, comm: str = "python") -> None:
    d = root / str(pid)
    d.mkdir()
    (d / "stat").write_text(f"{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 4194560", encoding="utf-8")
    (d / "cmdline").write_bytes(cmdline)


@pytest.fixture
def fake_proc(tmp_path: Path) -> Path:
    root = tmp_path / "proc"
    root.mkdir()
    # init: cmdline mentions uvicorn too — must never be targeted
    _proc(root, 1, 0, b"/sbin/docker-init\0--\0uvicorn\0app.main:app\0", comm="docker-init")
    _proc(root, 7, 1, b"/opt/venv/bin/python\0/opt/venv/bin/uvicorn\0app.main:app\0")
    _proc(root, 8, 0, b"python\0-m\0app.healthcheck\0")  # docker exec'd probe
    _proc(root, 9, 7, b"/opt/venv/bin/python\0-c\0uvicorn-helper\0")  # grandchild
    _proc(root, 10, 1, b"sleep\0infinity\0", comm="odd ) name (x")
    (root / "self").mkdir()
    (root / "42").mkdir()  # vanished between iterdir and read
    return root


def test_parent_pid_handles_parens_in_comm():
    assert healthcheck._parent_pid("10 (odd ) name (x) S 1 10 10") == 1
    assert healthcheck._parent_pid("garbage") is None


def test_find_target_pids_only_uvicorn_children_of_init(fake_proc):
    assert healthcheck.find_target_pids(fake_proc) == [7]


def test_find_target_pids_without_init_finds_nothing(tmp_path):
    root = tmp_path / "proc"
    root.mkdir()
    _proc(root, 1, 0, b"/opt/venv/bin/python\0/opt/venv/bin/uvicorn\0app.main:app\0")
    assert healthcheck.find_target_pids(root) == []
    assert healthcheck.find_target_pids(tmp_path / "missing") == []


def test_restart_dumps_stacks_then_sigkills(fake_proc, monkeypatch):
    monkeypatch.setattr(healthcheck, "STACK_DUMP_SIGNAL", FAKE_SIGUSR1)
    monkeypatch.setattr(healthcheck, "_SIGKILL", FAKE_SIGKILL)
    events: list[tuple] = []
    logs: list[str] = []
    monkeypatch.setattr(healthcheck, "_log", logs.append)
    killed = healthcheck.restart_frozen_app(
        "frozen",
        proc_root=fake_proc,
        kill=lambda pid, sig: events.append(("kill", pid, sig)),
        sleep=lambda s: events.append(("sleep", s)),
        grace_s=1.5,
    )
    assert killed == [7]
    assert events == [("kill", 7, FAKE_SIGUSR1), ("sleep", 1.5), ("kill", 7, FAKE_SIGKILL)]
    assert logs == [
        (
            "frozen; dumping thread stacks (SIGUSR1) then SIGKILL uvicorn pid(s) [7] "
            "so the restart policy restarts the container"
        )
    ]


def test_restart_reports_when_nothing_to_kill(tmp_path, monkeypatch):
    monkeypatch.setattr(healthcheck, "_SIGKILL", FAKE_SIGKILL)
    logs: list[str] = []
    monkeypatch.setattr(healthcheck, "_log", logs.append)
    calls: list = []
    assert healthcheck.restart_frozen_app(
        "down", proc_root=tmp_path, kill=lambda *a: calls.append(a)
    ) == []
    assert calls == []
    assert logs and logs[0].startswith("down; ") and "init: true" in logs[0]


@pytest.fixture
def run_main(tmp_path, monkeypatch):
    state = tmp_path / "failures"
    monkeypatch.setenv("BASTION_HEALTHCHECK_STATE_FILE", str(state))
    monkeypatch.delenv("BASTION_HEALTHCHECK_KILL_AFTER", raising=False)
    restarts: list[int] = []
    logs: list[str] = []
    monkeypatch.setattr(
        healthcheck, "restart_frozen_app", lambda reason: restarts.append(reason) or [7]
    )
    monkeypatch.setattr(healthcheck, "_log", logs.append)

    def _run(probe_result: str | None, previous: str | None = None) -> int:
        if previous is not None:
            state.write_text(previous, encoding="ascii")
        monkeypatch.setattr(healthcheck, "probe", lambda url, timeout: probe_result)
        return healthcheck.main()

    _run.state = state
    _run.restarts = restarts
    _run.logs = logs
    return _run


def test_success_resets_counter(run_main):
    assert run_main(None, previous="4") == 0
    assert run_main.state.read_text(encoding="ascii") == "0"
    assert run_main.restarts == []


def test_failures_below_threshold_only_count(run_main):
    assert run_main("URLError: timed out", previous="3") == 1
    assert run_main.state.read_text(encoding="ascii") == "4"
    assert run_main.restarts == []


def test_threshold_triggers_restart(run_main):
    previous = str(healthcheck.DEFAULT_KILL_AFTER - 1)
    assert run_main("TimeoutError: timed out", previous=previous) == 1
    assert run_main.restarts == [
        (
            f"/api/health failed {healthcheck.DEFAULT_KILL_AFTER} times in a row "
            "(TimeoutError: timed out)"
        )
    ]


def test_counter_is_bumped_before_probe(run_main, monkeypatch):
    """A probe killed by Docker's timeout still counts as a failure."""
    seen: list[str] = []

    def hanging_probe(url, timeout):
        seen.append(run_main.state.read_text(encoding="ascii"))
        return "killed"

    run_main.state.write_text("2", encoding="ascii")
    monkeypatch.setattr(healthcheck, "probe", hanging_probe)
    healthcheck.main()
    assert seen == ["3"]


def test_kill_after_zero_disables_restart(run_main, monkeypatch):
    monkeypatch.setenv("BASTION_HEALTHCHECK_KILL_AFTER", "0")
    assert run_main("boom", previous="99") == 1
    assert run_main.restarts == []


def test_unwritable_counter_never_kills(run_main, monkeypatch, tmp_path):
    monkeypatch.setenv("BASTION_HEALTHCHECK_STATE_FILE", str(tmp_path))  # a directory
    for _ in range(healthcheck.DEFAULT_KILL_AFTER + 2):
        assert run_main("boom") == 1
    assert run_main.restarts == []


def test_bad_env_values_fall_back_to_defaults(monkeypatch):
    monkeypatch.setenv("X_INT", "nope")
    monkeypatch.setenv("X_FLOAT", "")
    assert healthcheck._env_int("X_INT", 6) == 6
    assert healthcheck._env_float("X_FLOAT", 4.0) == 4.0
    monkeypatch.setenv("X_INT", "-3")
    assert healthcheck._env_int("X_INT", 6) == 0


class _Handler(BaseHTTPRequestHandler):
    status = 200

    def do_GET(self):
        self.send_response(type(self).status)
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, *args):  # silence
        pass


@pytest.mark.parametrize("status, expected_ok", [(200, True), (503, False)])
def test_probe_against_local_server(status, expected_ok):
    handler = type("H", (_Handler,), {"status": status})
    server = HTTPServer((LOOPBACK_V4_HOST, 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://{LOOPBACK_V4_HOST}:{server.server_port}/api/health"
        error = healthcheck.probe(url, timeout=2)
        assert (error is None) is expected_ok
    finally:
        server.shutdown()
        server.server_close()


def test_probe_connection_refused_is_failure():
    server = HTTPServer((LOOPBACK_V4_HOST, 0), _Handler)
    port = server.server_port
    server.server_close()
    assert healthcheck.probe(f"http://{LOOPBACK_V4_HOST}:{port}/", timeout=1)


def test_install_stack_dump_handler(monkeypatch):
    registered: list[tuple] = []
    monkeypatch.setattr(healthcheck, "STACK_DUMP_SIGNAL", FAKE_SIGUSR1)
    monkeypatch.setattr(
        healthcheck.faulthandler,
        "register",
        lambda sig, **kw: registered.append((sig, kw)),
        raising=False,
    )
    assert healthcheck.install_stack_dump_handler() is True
    assert registered == [(FAKE_SIGUSR1, {"all_threads": True, "chain": False})]

    monkeypatch.setattr(healthcheck, "STACK_DUMP_SIGNAL", None)
    assert healthcheck.install_stack_dump_handler() is False


def test_default_url_is_loopback_health():
    assert healthcheck.DEFAULT_URL == f"http://{LOOPBACK_V4_HOST}:8000/api/health"
