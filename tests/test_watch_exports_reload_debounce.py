"""bastion-nginx watcher: one reload per export burst (memcg OOM on back-to-back reloads).

The watcher script is sourced (its loop only runs when executed) and driven with
a scripted clock: ``watch_step <fingerprint> <epoch_second>`` per poll, with
``apply_changes`` stubbed to record when a reload would start.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WATCH = ROOT / "docker" / "nginx" / "watch-exports-reload.sh"

SETTLE = 5
MIN_INTERVAL = 15
MAX_DEFER = 60


def _working_bash() -> str | None:
    """A bash that actually runs (on Windows, PATH may resolve to the WSL launcher)."""
    candidates = [
        shutil.which("bash"),
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ]
    for cand in candidates:
        if not cand or not Path(cand).exists():
            continue
        try:
            probe = subprocess.run(
                [cand, "-c", "echo ok"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0 and probe.stdout.strip() == "ok":
            return cand
    return None


_BASH = _working_bash()


def _run(
    tmp_path: Path,
    polls: list[tuple[str, int]],
    *,
    boot: tuple[str, int] = ("fp0", -1000),
    apply_rc: int = 0,
) -> list[int]:
    """Return the epoch seconds at which a reload was attempted."""
    script = tmp_path / "watch.sh"
    # Working tree may be CRLF on Windows; the image strips \r the same way.
    script.write_text(
        WATCH.read_text(encoding="utf-8").replace("\r\n", "\n"),
        encoding="utf-8",
        newline="\n",
    )
    driver = "\n".join(
        [
            'source "$WATCH"',
            'apply_changes() { echo "RELOAD $now"; return "$APPLY_RC"; }',
            "after_reload() { :; }",
            f"watch_init {boot[0]} {boot[1]}",
            *(f"watch_step {fp} {t}" for fp, t in polls),
        ]
    )
    proc = subprocess.run(
        [_BASH, "-c", driver],
        env={
            "PATH": "/usr/bin:/bin",
            "WATCH": script.as_posix(),
            "APPLY_RC": str(apply_rc),
            "BASTION_EXPORTS_WATCH_SETTLE": str(SETTLE),
            "BASTION_RELOAD_MIN_INTERVAL": str(MIN_INTERVAL),
            "BASTION_EXPORTS_WATCH_MAX_DEFER": str(MAX_DEFER),
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return [
        int(ln.split()[1]) for ln in proc.stdout.splitlines() if ln.startswith("RELOAD ")
    ]


def _stable(fp: str, start: int, end: int) -> list[tuple[str, int]]:
    return [(fp, t) for t in range(start, end + 1, 2)]


pytestmark = pytest.mark.skipif(_BASH is None, reason="no working bash")


def test_bastion_app_restart_burst_gives_one_reload(tmp_path):
    # bastion-app restart rewrites exports file after file (one change per 2s poll).
    burst = [("fpA", 0), ("fpB", 2), ("fpC", 4), ("fpD", 6)]
    reloads = _run(tmp_path, burst + _stable("fpD", 8, 120))
    # Single reload, once the fingerprint stopped moving for SETTLE seconds.
    assert reloads == [12]


def test_second_burst_waits_for_min_interval(tmp_path):
    polls = [("fpA", 0), *_stable("fpA", 2, 12), ("fpB", 14), *_stable("fpB", 16, 80)]
    reloads = _run(tmp_path, polls)
    # fpA settles at 6; fpB settles at 20 but must wait 15s after the 6s reload.
    assert reloads == [6, 22]


def test_never_settling_exports_still_reload_after_max_defer(tmp_path):
    polls = [(f"fpX{t}", t) for t in range(0, 101, 2)]
    assert _run(tmp_path, polls) == [MAX_DEFER]


def test_failed_reload_is_retried_at_min_interval_not_every_poll(tmp_path):
    reloads = _run(tmp_path, [("fpA", 0), *_stable("fpA", 2, 60)], apply_rc=1)
    assert reloads == [6, 22, 38, 54]


def test_change_reverted_before_settling_does_not_reload(tmp_path):
    polls = [("fpA", 0), ("fp0", 2), *_stable("fp0", 4, 60)]
    assert _run(tmp_path, polls) == []


def test_boot_counts_as_a_load_for_min_interval(tmp_path):
    reloads = _run(tmp_path, [("fpA", 2), *_stable("fpA", 4, 40)], boot=("fp0", 0))
    assert reloads == [16]


def test_watcher_loop_only_runs_when_executed():
    text = WATCH.read_text(encoding="utf-8")
    assert 'if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then' in text
    entry = (ROOT / "docker" / "nginx" / "docker-entrypoint.sh").read_text(
        encoding="utf-8"
    )
    assert "  /watch-exports-reload.sh &" in entry


def test_nginx_bounds_old_workers_after_reload():
    conf = (ROOT / "docker" / "nginx" / "nginx.conf").read_text(encoding="utf-8")
    main_ctx = conf.split("http {", 1)[0]
    live = [
        ln.strip()
        for ln in main_ctx.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert "worker_shutdown_timeout 30s;" in live
