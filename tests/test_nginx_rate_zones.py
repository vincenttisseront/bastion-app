"""Every nginx ``limit_req zone=`` must be declared wherever nginx may load zones from.

Regression for v0.11.0: the ``activesync_auth`` zone was added to the image include
and the WAF export renderer but not to the nginx container's sync script. A stale
``exports/nginx-portal-rate-limits.conf`` (rendered by the previous app version)
then replaced the image file and nginx crash-looped with
"zero size shared memory zone".
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from app.bastion.nginx_waf_export import ensure_active_profile, render_rate_limits_conf

ROOT = Path(__file__).resolve().parents[1]
SYNC_SCRIPT = ROOT / "docker" / "nginx" / "sync-exports-to-confd.sh"
IMAGE_ZONES = ROOT / "docker" / "nginx" / "includes" / "nginx-portal-rate-limits.conf"

_USE_RE = re.compile(r"limit_req\s+zone=([a-z_]+)")
_DECL_RE = re.compile(r"zone=([a-z_]+):[1-9][0-9]*[mMkK]")


def _referenced_zones() -> set[str]:
    zones: set[str] = set()
    sources = [
        *(ROOT / "docker" / "nginx").rglob("*.conf"),
        *(ROOT / "docker" / "nginx").rglob("*.template"),
        *(ROOT / "nginx").rglob("*.conf"),
        *(ROOT / "nginx").rglob("*.j2"),
        *(ROOT / "app" / "bastion").glob("*.py"),
    ]
    for path in sources:
        zones.update(_USE_RE.findall(path.read_text(encoding="utf-8", errors="ignore")))
    return zones


def _script() -> str:
    return SYNC_SCRIPT.read_text(encoding="utf-8")


def _default_heredoc_zones() -> set[str]:
    body = _script().split("_write_default_rate_limits() {", 1)[1].split("\nEOF", 1)[0]
    return set(_DECL_RE.findall(body))


def _ensured_zones() -> set[str]:
    body = _script().split("_ensure_required_rate_zones() {", 1)[1].split("\n}", 1)[0]
    return set(re.findall(r"_ensure_rate_zone\s+([a-z_]+)\s", body))


def test_references_found():
    assert {"portal_login", "portal_api", "activesync_auth"} <= _referenced_zones()


@pytest.mark.parametrize(
    "where, declared",
    [
        ("image include", lambda db: set(_DECL_RE.findall(IMAGE_ZONES.read_text(encoding="utf-8")))),
        ("sync script defaults", lambda db: _default_heredoc_zones()),
        ("sync script ensure list", lambda db: _ensured_zones()),
        (
            "WAF export renderer",
            lambda db: set(_DECL_RE.findall(render_rate_limits_conf(ensure_active_profile(db)))),
        ),
    ],
)
def test_every_referenced_zone_is_declared(db_session, where, declared):
    missing = _referenced_zones() - declared(db_session)
    assert not missing, f"{where} lacks rate zones referenced by vhosts: {sorted(missing)}"


def _ensure_block() -> str:
    text = _script()
    start = text.index("RATE_LIMITS_CONF=")
    end = text.index("\n}", text.index("_ensure_required_rate_zones() {")) + 2
    return text[start:end]


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
                [cand, "-c", "echo ok"], capture_output=True, text=True, timeout=10
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0 and probe.stdout.strip() == "ok":
            return cand
    return None


_BASH = _working_bash()


@pytest.mark.skipif(_BASH is None, reason="no working bash")
def test_stale_export_gets_missing_zone_appended_once(tmp_path):
    conf = tmp_path / "nginx-portal-rate-limits.conf"
    # What a 0.10.x app rendered: no activesync_auth zone.
    conf.write_text(
        "limit_req_status 429;\n"
        "limit_req_zone $binary_remote_addr zone=portal_login:10m rate=3r/s;\n"
        "limit_req_zone $binary_remote_addr zone=portal_api:10m rate=50r/s;\n"
        "limit_req_zone $binary_remote_addr zone=portal_standard:10m rate=20r/s;\n"
        "limit_req_zone $binary_remote_addr zone=portal_unknown_host:10m rate=5r/s;\n",
        encoding="utf-8",
    )
    script = _ensure_block() + "\n_ensure_required_rate_zones\n_ensure_required_rate_zones\n"
    proc = subprocess.run(
        [_BASH, "-c", script],
        env={"RATE_LIMITS_CONF": conf.as_posix(), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = conf.read_text(encoding="utf-8")
    assert out.count("zone=activesync_auth:10m rate=20r/s;") == 1  # idempotent
    assert "zone=portal_login:10m rate=3r/s;" in out  # existing rates untouched
    assert out.count("zone=portal_login:") == 1
    assert "lacks activesync_auth zone" in proc.stderr
