"""Tests for scripts/purge-portal-db-backups.py"""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "purge-portal-db-backups.py"
_spec = importlib.util.spec_from_file_location("purge_portal_db_backups", _SCRIPT)
_mod = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules["purge_portal_db_backups"] = _mod
_spec.loader.exec_module(_mod)
purge_portal_db_backups = _mod.purge_portal_db_backups


def _touch_backup(data_dir: Path, stamp: str) -> None:
    (data_dir / f"portal.db.bak.{stamp}").write_bytes(b"x" * 100)


def test_purge_keeps_five_latest(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    base = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)
    stamps = []
    for i in range(10):
        stamp = (base + timedelta(hours=i)).strftime("%Y%m%dT%H%M%S")
        stamps.append(stamp)
        _touch_backup(data, stamp)
    _, removed = purge_portal_db_backups(data, keep_count=5, daily_days=7)
    assert removed == 5
    assert len(list(data.glob("portal.db.bak.*"))) == 5
    assert (data / f"portal.db.bak.{stamps[-1]}").is_file()


def test_purge_gzips_older_kept(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    _touch_backup(data, "20260817T120000")
    _touch_backup(data, "20260819T120000")
    purge_portal_db_backups(data, keep_count=1, daily_days=7)
    assert (data / "portal.db.bak.20260819T120000").is_file()
    assert (data / "portal.db.bak.20260817T120000.gz").is_file()
