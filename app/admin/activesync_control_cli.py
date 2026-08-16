"""CLI one-shot: enable ActiveSync device control for an app (inventory backfill).

Usage::

    python -m app.admin.activesync_control_cli mail --preview
    python -m app.admin.activesync_control_cli mail --enable --pending-id ID1 --pending-id ID2
    python -m app.admin.activesync_control_cli mail --enable   # only if zero pending
    python -m app.admin.activesync_control_cli mail --disable
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
        help="Print inventory summary + pending DeviceIds (freeze list) without changing anything",
    )
    parser.add_argument(
        "--enable",
        action="store_true",
        help="Arm the gate using the freeze list (--pending-id)",
    )
    parser.add_argument(
        "--disable",
        action="store_true",
        help="Suspend enforcement (keep inventory)",
    )
    parser.add_argument(
        "--pending-id",
        action="append",
        default=[],
        dest="pending_ids",
        metavar="DEVICE_ID",
        help="DeviceId from a prior --preview (repeatable). Case-sensitive.",
    )
    parser.add_argument(
        "--actor",
        default="cli",
        help="decided_by / audit actor (default: cli)",
    )
    args = parser.parse_args(argv)

    if sum(bool(x) for x in (args.preview, args.enable, args.disable)) != 1:
        print(
            "choose exactly one of --preview / --enable / --disable",
            file=sys.stderr,
        )
        return 2

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
            for d in preview["pending"]:
                print(f"PENDING\t{d.device_id}\t{d.user_key}\t{d.device_type or '-'}")
            if preview["pending"]:
                print(
                    "# then: --enable "
                    + " ".join(f"--pending-id {d.device_id}" for d in preview["pending"]),
                    file=sys.stderr,
                )
            else:
                print("# no pending — --enable with no --pending-id is enough", file=sys.stderr)
            return 0
        if args.disable:
            device_service.disable_device_control(db, app, actor=args.actor)
            print("control suspended")
            return 0
        result = device_service.enable_device_control(
            db,
            app,
            actor=args.actor,
            pending_device_ids=list(args.pending_ids),
        )
        print(
            f"control enabled; approved_from_pending={result['approved_from_pending']} "
            f"left_pending={result.get('left_pending', 0)}"
        )
        return 0
    except device_service.DeviceDecisionError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
