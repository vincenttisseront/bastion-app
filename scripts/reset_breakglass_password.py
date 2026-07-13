#!/usr/bin/env python3
"""Reset a break-glass account password (bcrypt, compatible with verify_breakglass_password)."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.database import SessionLocal  # noqa: E402
from app.breakglass_store import set_breakglass_password  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset break-glass local admin password")
    parser.add_argument("--username", default="admin", help="Break-glass username (default: admin)")
    args = parser.parse_args()

    password = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("ERROR: passwords do not match", file=sys.stderr)
        return 1
    if len(password) < 12:
        print("ERROR: password must be at least 12 characters", file=sys.stderr)
        return 1

    db = SessionLocal()
    try:
        account = set_breakglass_password(db, args.username, password)
        print(f"OK: break-glass password updated for user '{account.username}'")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
