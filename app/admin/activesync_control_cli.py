"""CLI one-shot: enable ActiveSync device control for an app (inventory backfill).

Usage::

    python -m app.admin.activesync_control_cli mail
    python -m app.admin.activesync_control_cli mail --disable
    python -m app.admin.activesync_control_cli mail --preview
"""

from __future__ import annotations

import argparse
import sys

from app.database import SessionLocal
from app.models import App
from app.subdomain import activesync_device_service as device_service


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("slug", help="Application slug (e.g. mail)")
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Print inventory summary without changing anything",
    )
    parser.add_argument(
        "--disable",
        action="store_true",
        help="Suspend enforcement (keep inventory)",
    )
    parser.add_argument(
        "--actor",
        default="cli",
        help="decided_by / audit actor (default: cli)",
    )
    args = parser.parse_args(argv)

    db = SessionLocal()
    try:
        app = db.query(App).filter(App.slug == args.slug).first()
        if app is None:
            print(f"unknown app slug: {args.slug}", file=sys.stderr)
            return 1
        preview = device_service.preview_device_control(db, app)
        print(
            f"{app.slug}: total={preview['total']} pending={preview['pending_count']} "
            f"approved={preview['approved_count']} blocked={preview['blocked_count']} "
            f"control={preview['control_enabled']}"
        )
        if args.preview:
            return 0
        if args.disable:
            device_service.disable_device_control(db, app, actor=args.actor)
            print("control suspended")
            return 0
        result = device_service.enable_device_control(db, app, actor=args.actor)
        print(
            f"control enabled; approved_from_pending={result['approved_from_pending']}"
        )
        return 0
    except device_service.DeviceDecisionError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
