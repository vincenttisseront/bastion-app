#!/usr/bin/env python3
"""Purge portal.db.bak.* — keep N latest + one per day for D days; gzip older kept copies."""

from __future__ import annotations

import gzip
import os
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA_DIR = Path(os.environ.get("DATA_DIR", "/tools/portal/data"))
KEEP_COUNT = max(1, int(os.environ.get("KEEP_COUNT", "5")))
DAILY_DAYS = max(1, int(os.environ.get("DAILY_DAYS", "7")))

_STAMP = re.compile(r"^portal\.db\.bak\.(\d{8}T\d{6})(?:\.gz)?$")


def _parse(path: Path) -> datetime | None:
    m = _STAMP.match(path.name)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _base(path: Path) -> Path:
    return path.with_name(path.name[:-3]) if path.name.endswith(".gz") else path


def _gzip_file(path: Path) -> None:
    gz = path.with_name(path.name + ".gz")
    if gz.exists():
        path.unlink(missing_ok=True)
        return
    with path.open("rb") as src, gzip.open(gz, "wb", compresslevel=9) as dst:
        shutil.copyfileobj(src, dst)
    path.unlink(missing_ok=True)


def purge_portal_db_backups(
    data_dir: Path,
    *,
    keep_count: int = 5,
    daily_days: int = 7,
) -> tuple[int, int]:
    """Return (kept_count, removed_count)."""
    entries: list[tuple[datetime, Path]] = []
    for path in sorted(data_dir.glob("portal.db.bak.*")):
        if not path.is_file():
            continue
        dt = _parse(path)
        if dt is None:
            continue
        entries.append((dt, path))
    entries.sort(key=lambda x: x[0], reverse=True)

    keep: set[Path] = set()
    for _, path in entries[:keep_count]:
        keep.add(_base(path))

    cutoff = datetime.now(timezone.utc) - timedelta(days=daily_days)
    by_day: dict = {}
    for dt, path in entries:
        base = _base(path)
        if dt < cutoff:
            continue
        day = dt.date()
        if day not in by_day or dt > by_day[day][0]:
            by_day[day] = (dt, base)
    keep.update(base for _, base in by_day.values())

    top_n = {_base(p) for _, p in entries[:keep_count]}
    removed = 0
    seen: set[Path] = set()
    for _, path in entries:
        base = _base(path)
        if base in seen:
            continue
        seen.add(base)
        if base not in keep:
            base.unlink(missing_ok=True)
            _gzip = base.with_name(base.name + ".gz")
            _gzip.unlink(missing_ok=True)
            removed += 1
            continue
        if base not in top_n and base.is_file():
            _gzip_file(base)
    return len(keep), removed


def main() -> int:
    kept, removed = purge_portal_db_backups(
        DATA_DIR, keep_count=KEEP_COUNT, daily_days=DAILY_DAYS
    )
    print(f"purge-portal-db-backups: kept={kept} removed={removed} dir={DATA_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
