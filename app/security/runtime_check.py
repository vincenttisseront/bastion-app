"""Container runtime hardening probe (v3.2) — exposed in Admin WAF #technical."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def _is_root() -> bool:
    try:
        return int(os.getuid()) == 0
    except AttributeError:
        # Windows / exotic — treat as non-hardened for this signal.
        return True


def _read_only_root_fs() -> bool:
    """True when creating a file on the container root FS fails (read_only: true)."""
    test_path = Path("/.bastion_runtime_write_test")
    try:
        test_path.write_text("x", encoding="utf-8")
        try:
            test_path.unlink(missing_ok=True)
        except OSError:
            pass
        return False
    except OSError:
        return True


def _no_new_privileges() -> bool | None:
    """Read NoNewPrivs from /proc/self/status. None if unavailable."""
    status = Path("/proc/self/status")
    if not status.is_file():
        return None
    try:
        for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("NoNewPrivs:"):
                return "1" in line.split(":", 1)[1]
    except OSError:
        return None
    return None


def _cap_eff_emptyish() -> bool | None:
    """Best-effort: CapEff all-zero (or only NET_BIND residual) after cap_drop ALL."""
    status = Path("/proc/self/status")
    if not status.is_file():
        return None
    try:
        for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("CapEff:"):
                hex_val = line.split(":", 1)[1].strip().lower()
                # All zero = fully dropped; tiny residual (NET_BIND) still "dropped-ish".
                try:
                    value = int(hex_val, 16)
                except ValueError:
                    return None
                # CAP_NET_BIND_SERVICE is bit 10 (0x400). Allow that alone.
                return value == 0 or value == 0x400
    except OSError:
        return None
    return None


def check_runtime_hardening() -> dict[str, Any]:
    """Evaluate isolation / privilege level of the current container process."""
    is_root = _is_root()
    read_only_fs = _read_only_root_fs()
    no_new_privs = _no_new_privileges()
    caps_ok = _cap_eff_emptyish()

    hardened = (
        (not is_root)
        and read_only_fs
        and (no_new_privs is True)
    )
    return {
        "is_root": is_root,
        "uid": int(os.getuid()) if hasattr(os, "getuid") else None,
        "read_only_fs": read_only_fs,
        "no_new_privileges": no_new_privs,
        "caps_dropped": caps_ok,
        "runtime_status": "hardened" if hardened else "loose",
        "ok": hardened,
    }
