"""Unit tests for scripts/bump_version.py (semver helpers)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bump_version.py"


def _load():
    spec = importlib.util.spec_from_file_location("bump_version", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_bump_semver_kinds():
    bump = _load()
    assert bump.bump_semver("0.10.0", major=False, minor=False, patch=True) == "0.10.1"
    assert bump.bump_semver("0.10.1", major=False, minor=True, patch=False) == "0.11.0"
    assert bump.bump_semver("0.10.1", major=True, minor=False, patch=False) == "1.0.0"


def test_read_current_version_matches_constants():
    bump = _load()
    assert bump.read_current_version() == bump.SEMVER_RE.match(
        bump.read_current_version()
    ).group(0)


def test_replace_version_preserves_v_prefix():
    bump = _load()
    sample = "pin :v0.10.0 and 0.10.0"
    assert bump._replace_version(sample, "0.10.0", "0.10.1") == "pin :v0.10.1 and 0.10.1"


def test_invalid_set_rejected(monkeypatch: pytest.MonkeyPatch):
    bump = _load()
    with pytest.raises(SystemExit):
        bump.main(["--set", "v0.10.1"])
