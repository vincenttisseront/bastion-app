#!/usr/bin/env python3
"""Regenerate docker/nginx/errors/ (static error pages baked into bastion-nginx).

Source of truth: app/web/static_error_pages.py + app/templates/errors/static_page.html.
tests/test_static_error_pages.py fails when the committed files drift.

Usage: python scripts/generate_nginx_error_pages.py [--check]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.web.static_error_pages import (
    build_static_error_files,
    write_static_error_files,
)

ERRORS_DIR = ROOT / "docker" / "nginx" / "errors"


def _drift() -> list[str]:
    expected = build_static_error_files()
    problems: list[str] = []
    for name, content in expected.items():
        path = ERRORS_DIR / name
        if not path.is_file():
            problems.append(f"missing {name}")
        elif path.read_text(encoding="utf-8").replace("\r\n", "\n") != content:
            problems.append(f"outdated {name}")
    for path in ERRORS_DIR.iterdir():
        if path.is_file() and path.name not in expected:
            problems.append(f"stale {path.name}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if files drift")
    args = parser.parse_args()
    if args.check:
        problems = _drift()
        for line in problems:
            print(line)
        return 1 if problems else 0
    for path in write_static_error_files(ERRORS_DIR):
        print(path.relative_to(ROOT).as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
