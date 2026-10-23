#!/usr/bin/env python3
"""Bump Bastion Pro release version across all pins (source of truth sync).

Usage:
  python scripts/bump_version.py --patch
  python scripts/bump_version.py --minor
  python scripts/bump_version.py --major
  python scripts/bump_version.py --set 0.11.0
  python scripts/bump_version.py --show

Pins updated:
  - app/web/constants.py (APP_VERSION — runtime / footer / smoke)
  - pyproject.toml + uv.lock (project package)
  - sonar-project.properties
  - ansible role defaults (sso_portal_app_version)
  - README.md, deploy/README.md, .env.example, deploy/.env.example
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
CONSTANTS = ROOT / "app" / "web" / "constants.py"

# Plain-text / yaml / toml files: replace old → new as substring (covers vX.Y.Z too).
TEXT_PINS = [
    ROOT / "pyproject.toml",
    ROOT / "sonar-project.properties",
    ROOT / "ansible" / "roles" / "sso_portal" / "defaults" / "main.yml",
    ROOT / "ansible" / "roles" / "bastion_app_docker" / "defaults" / "main.yml",
    ROOT / "README.md",
    ROOT / "deploy" / "README.md",
    ROOT / ".env.example",
    ROOT / "deploy" / ".env.example",
]


def read_current_version() -> str:
    text = CONSTANTS.read_text(encoding="utf-8")
    match = re.search(r'^APP_VERSION\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
    if not match:
        raise SystemExit(f"APP_VERSION not found in {CONSTANTS}")
    version = match.group(1).strip()
    if not SEMVER_RE.match(version):
        raise SystemExit(f"APP_VERSION {version!r} is not X.Y.Z")
    return version


def bump_semver(current: str, *, major: bool, minor: bool, patch: bool) -> str:
    m = SEMVER_RE.match(current)
    if not m:
        raise ValueError(current)
    maj, min_, pat = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    if major:
        return f"{maj + 1}.0.0"
    if minor:
        return f"{maj}.{min_ + 1}.0"
    if patch:
        return f"{maj}.{min_}.{pat + 1}"
    raise ValueError("no bump kind")


def _replace_version(text: str, old: str, new: str) -> str:
    if old not in text:
        return text
    return text.replace(old, new)


def _update_constants(old: str, new: str) -> None:
    text = CONSTANTS.read_text(encoding="utf-8")
    updated, n = re.subn(
        rf'^(APP_VERSION\s*=\s*"){re.escape(old)}("\s*)$',
        rf"\g<1>{new}\2",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if n != 1:
        raise SystemExit(f"failed to update APP_VERSION in {CONSTANTS}")
    CONSTANTS.write_text(updated, encoding="utf-8")


def _update_uv_lock(old: str, new: str) -> None:
    path = ROOT / "uv.lock"
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    # Only the editable bastion-app package stanza.
    pattern = (
        r'(name = "bastion-app"\nversion = ")' + re.escape(old) + r'(")'
    )
    updated, n = re.subn(pattern, rf"\g<1>{new}\2", text, count=1)
    if n != 1:
        # Fallback: pyproject may already differ; try any bastion-app version line.
        pattern2 = r'(name = "bastion-app"\nversion = ")[^"]+(")'
        updated, n = re.subn(pattern2, rf"\g<1>{new}\2", text, count=1)
        if n != 1:
            raise SystemExit(f"failed to update bastion-app version in {path}")
    path.write_text(updated, encoding="utf-8")


def apply_version(old: str, new: str) -> list[str]:
    if old == new:
        return []
    touched: list[str] = []
    _update_constants(old, new)
    touched.append(str(CONSTANTS.relative_to(ROOT)))

    for path in TEXT_PINS:
        if not path.is_file():
            continue
        raw = path.read_text(encoding="utf-8")
        updated = _replace_version(raw, old, new)
        if updated == raw:
            # Still require pyproject / sonar / ansible to contain the pin.
            rel = str(path.relative_to(ROOT))
            if rel in {
                "pyproject.toml",
                "sonar-project.properties",
                "ansible/roles/sso_portal/defaults/main.yml",
                "ansible/roles/bastion_app_docker/defaults/main.yml",
            }:
                raise SystemExit(f"expected version {old} missing in {rel}")
            continue
        path.write_text(updated, encoding="utf-8")
        touched.append(str(path.relative_to(ROOT)))

    _update_uv_lock(old, new)
    if (ROOT / "uv.lock").is_file():
        touched.append("uv.lock")
    return touched


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--show", action="store_true", help="print current version")
    group.add_argument("--patch", action="store_true", help="X.Y.Z → X.Y.(Z+1)")
    group.add_argument("--minor", action="store_true", help="X.Y.Z → X.(Y+1).0")
    group.add_argument("--major", action="store_true", help="X.Y.Z → (X+1).0.0")
    group.add_argument("--set", metavar="X.Y.Z", help="set exact version")
    args = parser.parse_args(argv)

    current = read_current_version()
    if args.show:
        print(current)
        return 0

    if args.set:
        if not SEMVER_RE.match(args.set):
            raise SystemExit(f"--set expects X.Y.Z, got {args.set!r}")
        new = args.set
    else:
        new = bump_semver(
            current, major=args.major, minor=args.minor, patch=args.patch
        )

    touched = apply_version(current, new)
    print(f"{current} → {new}")
    for path in touched:
        print(f"  updated {path}")
    print("Next: commit, tag v{0}, then scripts/publish_images.ps1".format(new))
    return 0


if __name__ == "__main__":
    sys.exit(main())
