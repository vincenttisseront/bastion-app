"""Container healthcheck that also restarts a frozen bastion-app.

Run by Docker as ``python -m app.healthcheck`` (exec form: the DHI runtime image
has no shell). Imports only the stdlib and ``app.ip_cidrs`` so it stays cheap.

Incident 2026-11-06: uvicorn froze with the GIL held (SQLCipher open/close
deadlock, see ``app.db_cipher``). Docker flagged the container *unhealthy* for
hours, but ``restart: unless-stopped`` never restarts an unhealthy container,
and nothing inside the frozen interpreter can run (no Python watchdog thread,
no Python-level SIGTERM handler).

Each run of this probe, in its own process:

1. bumps a consecutive-failure counter in tmpfs *before* probing, so a probe
   killed by Docker's healthcheck ``timeout`` still counts as a failure;
2. GETs ``/api/health`` on loopback; success resets the counter (exit 0);
3. after ``BASTION_HEALTHCHECK_KILL_AFTER`` consecutive failures (default 6,
   about 3 min at ``interval: 30s``; ``0`` disables), sends SIGUSR1 to uvicorn
   (``faulthandler`` dumps every thread's Python stack to the container log,
   without needing the GIL), then SIGKILL.

Compose runs the service with ``init: true``: docker-init is PID 1 and uvicorn
its child. SIGKILL is then delivered (the kernel drops SIGKILL sent to a PID
namespace's init from inside it), docker-init exits with uvicorn's status, the
container stops and the restart policy starts it again. No Docker socket, no
capability: the probe runs with uvicorn's UID. Without an init (plain
``docker run``), uvicorn is PID 1, nothing is killed and the probe only reports
unhealthy, as before.
"""

from __future__ import annotations

import faulthandler
import os
import signal
import sys
import time
import urllib.request
from pathlib import Path

from app.ip_cidrs import LOOPBACK_V4_HOST

DEFAULT_URL = f"http://{LOOPBACK_V4_HOST}:8000/api/health"
DEFAULT_STATE_FILE = "/tmp/bastion-healthcheck.failures"  # tmpfs: reset on restart
DEFAULT_KILL_AFTER = 6
DEFAULT_TIMEOUT_S = 4.0
STACK_DUMP_GRACE_S = 2.0
TARGET_MARKER = b"uvicorn"
# Not used by uvicorn; faulthandler.register is POSIX-only.
STACK_DUMP_SIGNAL = getattr(signal, "SIGUSR1", None)
_SIGKILL = getattr(signal, "SIGKILL", None)


def install_stack_dump_handler() -> bool:
    """Dump all threads' Python stacks to stderr on SIGUSR1 (no GIL needed).

    Called at app startup so a frozen process still leaves its stacks in
    ``docker logs`` when the healthcheck kills it.
    """
    if STACK_DUMP_SIGNAL is None or not hasattr(faulthandler, "register"):
        return False
    faulthandler.register(STACK_DUMP_SIGNAL, all_threads=True, chain=False)
    return True


def _env_int(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    try:
        return max(0, int(raw)) if raw else default
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    try:
        return max(0.1, float(raw)) if raw else default
    except ValueError:
        return default


def read_failures(path: Path) -> int:
    try:
        return max(0, int(path.read_text(encoding="ascii").strip() or 0))
    except (OSError, ValueError):
        return 0


def write_failures(path: Path, count: int) -> bool:
    try:
        path.write_text(str(count), encoding="ascii")
        return True
    except OSError:
        return False


def probe(url: str, timeout: float) -> str | None:
    """Return None when ``url`` answers 200, else a short error string."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status == 200:
                return None
            return f"HTTP {resp.status}"
    except Exception as exc:  # noqa: BLE001 — any failure is "unhealthy"
        return f"{type(exc).__name__}: {exc}"


def _parent_pid(stat_text: str) -> int | None:
    # /proc/<pid>/stat: "pid (comm) state ppid ..." — comm may contain spaces/parens.
    fields = stat_text.rsplit(")", 1)[-1].split()
    try:
        return int(fields[1])
    except (IndexError, ValueError):
        return None


def find_target_pids(proc_root: Path = Path("/proc"), marker: bytes = TARGET_MARKER) -> list[int]:
    """PIDs whose parent is PID 1 (the init) and whose cmdline contains ``marker``.

    PID 1 itself is never returned: without ``init: true`` it *is* uvicorn and
    cannot be killed from inside the container anyway.
    """
    own = os.getpid()
    pids: list[int] = []
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return pids
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid in (1, own):
            continue
        try:
            ppid = _parent_pid((entry / "stat").read_text(encoding="utf-8", errors="replace"))
            cmdline = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if ppid == 1 and marker in cmdline:
            pids.append(pid)
    return sorted(pids)


def _log(message: str, *, container_log: bool = True) -> None:
    """Healthcheck output (``docker inspect``) and, best effort, the container log."""
    line = f"bastion-healthcheck: {message}\n"
    sys.stdout.write(line)
    if not container_log:
        return
    try:
        # PID 1's stderr is the container log stream (same UID, no capability).
        with open("/proc/1/fd/2", "a", encoding="utf-8") as stream:
            stream.write(line)
    except OSError:
        pass


def restart_frozen_app(
    reason: str = "",
    *,
    proc_root: Path = Path("/proc"),
    kill=os.kill,
    sleep=time.sleep,
    grace_s: float = STACK_DUMP_GRACE_S,
    repeated: bool = False,
) -> list[int]:
    """SIGUSR1 (stack dump) then SIGKILL every uvicorn child of PID 1.

    ``repeated``: an earlier probe already gave up; don't write the "nothing
    to kill" line to the container log again (no init, or a one-off command).
    """
    pids = find_target_pids(proc_root)
    if not pids or _SIGKILL is None:
        _log(
            f"{reason}; no uvicorn child of PID 1 to kill (is compose `init: true` set?)",
            container_log=not repeated,
        )
        return []
    # Log first: once uvicorn dies the whole container (this probe included) stops.
    _log(
        f"{reason}; dumping thread stacks (SIGUSR1) then SIGKILL uvicorn pid(s) "
        f"{pids} so the restart policy restarts the container"
    )
    if STACK_DUMP_SIGNAL is not None:
        for pid in pids:
            try:
                kill(pid, STACK_DUMP_SIGNAL)
            except OSError:
                pass
        sleep(grace_s)
    killed: list[int] = []
    for pid in pids:
        try:
            kill(pid, _SIGKILL)
            killed.append(pid)
        except OSError as exc:
            _log(f"SIGKILL pid={pid} failed: {exc}")
    return killed


def main() -> int:
    url = os.environ.get("BASTION_HEALTHCHECK_URL") or DEFAULT_URL
    state = Path(os.environ.get("BASTION_HEALTHCHECK_STATE_FILE") or DEFAULT_STATE_FILE)
    kill_after = _env_int("BASTION_HEALTHCHECK_KILL_AFTER", DEFAULT_KILL_AFTER)
    timeout = _env_float("BASTION_HEALTHCHECK_TIMEOUT_S", DEFAULT_TIMEOUT_S)

    failures = read_failures(state) + 1
    tracked = write_failures(state, failures)  # pessimistic: counts if we get killed
    error = probe(url, timeout)
    if error is None:
        write_failures(state, 0)
        return 0

    if not tracked:
        sys.stdout.write(f"bastion-healthcheck: {error} (failure counter not writable)\n")
        return 1
    sys.stdout.write(f"bastion-healthcheck: {error} ({failures}/{kill_after or 'off'})\n")
    if kill_after and failures >= kill_after:
        restart_frozen_app(
            f"/api/health failed {failures} times in a row ({error})",
            repeated=failures > kill_after,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
